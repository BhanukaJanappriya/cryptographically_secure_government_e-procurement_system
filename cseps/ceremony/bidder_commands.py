"""
CSePS Bidder Commands
======================
Bidder actions:
  - Browse open procurements
  - Submit sealed encrypted bid
  - View submitted bid envelopes
"""

import sys
import json
import secrets
from datetime import datetime, timezone

from config import (
    ROLE_BIDDER, STATUS_OPEN,
    C_GREEN, C_YELLOW, C_CYAN, C_BOLD, C_RESET, C_DIM, C_MAGENTA,
)
from crypto_engine import (
    HybridEncryption, CommitmentScheme, DigitalSignature, TrustedTimestamp,
)
from storage import (
    UserStore, SessionStore, ProcurementStore, BidStore, LedgerStore,
)
from display import (
    print_section_banner, print_result_banner, print_phase_banner,
    print_success, print_error, print_warning, print_info,
    print_key_value_block, print_key_value, print_crypto, print_ledger,
    print_step, print_table, print_hash_line, status_badge, blank, divider,
    prompt, prompt_float, prompt_int, prompt_confirm,
    working, short_hash,
)


def _require_bidder() -> dict:
    return SessionStore.require_role(ROLE_BIDDER)


# ─────────────────────────── Submit Bid ───────────────────────────────────────

def cmd_submit_bid(args: list[str]):
    """Submit a sealed encrypted bid for a procurement."""
    session = _require_bidder()
    user    = UserStore.get_user(session["username"])

    print_section_banner("Submit Sealed Bid", "📨")
    blank()

    proc_id = args[0] if args else prompt("Procurement ID")
    proc    = ProcurementStore.get(proc_id)

    if not proc:
        print_error(f"Procurement '{proc_id}' not found.")
        sys.exit(1)
    if proc["status"] != STATUS_OPEN:
        print_error(f"Procurement '{proc_id}' is {proc['status']}. Bidding is closed.")
        sys.exit(1)
    if BidStore.bidder_has_submitted(proc_id, session["username"]):
        print_error("You have already submitted a bid for this procurement.")
        sys.exit(1)

    # Show procurement details
    print(f"  {C_BOLD}Procurement:{C_RESET} {proc['title']}")
    print_key_value_block([
        ("ID",          proc_id),
        ("Category",    proc["category"]),
        ("Budget",      f"${proc['budget']:,.2f}"),
        ("Deadline",    proc["deadline"]),
        ("Description", proc["description"][:80]),
    ])
    blank()
    divider()
    blank()
    print(f"  {C_DIM}Enter your bid details (will be encrypted before submission):{C_RESET}")
    blank()

    # Collect bid details
    item_desc    = prompt("Item/Service description")
    unit_price   = prompt_float("Unit price (USD)", min_val=0.01)
    quantity     = prompt_int("Quantity", min_val=1)
    total_amount = unit_price * quantity
    delivery_days = prompt_int("Delivery / completion time (days)", min_val=1)
    company_reg  = prompt("Company registration number")
    notes        = prompt("Additional notes (optional)", required=False)

    print()
    print_key_value_block([
        ("Unit Price",     f"${unit_price:,.2f}"),
        ("Quantity",       str(quantity)),
        ("TOTAL AMOUNT",   f"${total_amount:,.2f}"),
        ("Delivery",       f"{delivery_days} days"),
    ])
    blank()

    if not prompt_confirm("Submit this bid? (cannot be changed after submission)"):
        print_warning("Bid cancelled.")
        return

    # Load private key for signing
    priv_pem = UserStore.load_private_key(session["username"])
    if not priv_pem:
        print_error("Private key not found.")
        sys.exit(1)

    print_phase_banner(3, "Sealing Bid Cryptographically")

    # Build payload
    payload = {
        "procurement_id":  proc_id,
        "item_description": item_desc,
        "unit_price":       unit_price,
        "quantity":         quantity,
        "total_amount":     total_amount,
        "delivery_days":    delivery_days,
        "company_reg":      company_reg,
        "notes":            notes,
        "nonce_salt":       secrets.token_hex(16),
        "submitted_at":     datetime.now(timezone.utc).isoformat(),
    }

    payload_json = json.dumps(payload, sort_keys=True).encode()

    # Step 1: Hybrid encrypt
    print_step("ENCRYPT", "ECDH key agreement + AES-256-GCM encryption …")
    authority = UserStore.get_user(proc["authority_username"])
    enc_data  = HybridEncryption.encrypt(payload_json, authority["public_key_pem"])
    print_crypto(f"Encrypted with authority public key (P-384 + AES-256-GCM)")

    # Step 2: Commitment
    print_step("COMMIT ", "Computing SHA3-256 commitment …")
    commitment = CommitmentScheme.commit(
        enc_data["ciphertext_b64"], enc_data["nonce_b64"]
    )
    print_crypto(f"Commitment: {commitment[:32]}…")

    # Step 3: Sign commitment
    print_step("SIGN   ", "ECDSA P-384 signing commitment …")
    sig_b64 = DigitalSignature.sign(commitment.encode(), priv_pem)
    print_crypto(f"Signature:  {sig_b64[:32]}…")

    # Step 4: Timestamp
    print_step("STAMP  ", "Issuing trusted timestamp …")
    ts_token = TrustedTimestamp.issue(commitment)
    print_crypto(f"Timestamp:  {ts_token['issued_at']}")

    # Assemble envelope
    envelope_id = f"ENV-{secrets.token_hex(6).upper()}"
    ts          = datetime.now(timezone.utc).isoformat()

    envelope = {
        "envelope_id":      envelope_id,
        "proc_id":          proc_id,
        "bidder_username":  session["username"],
        "bidder_name":      user["full_name"],
        "organisation":     user["organisation"],
        "submitted_at":     ts,
        "commitment_hash":  commitment,
        "signature_b64":    sig_b64,
        "enc_data":         enc_data,
        "ts_token":         ts_token,
    }

    # Persist
    BidStore.store_bid(proc_id, envelope)
    ProcurementStore.increment_bid_count(proc_id)

    # Ledger
    entry = LedgerStore.append(
        event_type="BID_SUBMITTED",
        actor=session["username"],
        proc_id=proc_id,
        payload={
            "envelope_id":   envelope_id,
            "commitment":    commitment,
            "key_fingerprint": DigitalSignature.verify.__module__,
        },
    )
    print_ledger(f"Ledger entry #{entry['seq']} | Chain: {short_hash(entry['chain_hash'])}")

    print_result_banner(f"Bid submitted successfully! Envelope: {envelope_id}", ok=True)
    blank()
    print_key_value_block([
        ("Envelope ID",       envelope_id),
        ("Commitment Hash",   f"{commitment[:24]}…"),
        ("Timestamp",         ts[:19].replace("T", " ") + " UTC"),
        ("Ledger Entry",      f"#{entry['seq']}"),
        ("Status",            "SEALED — unreadable until deadline"),
    ])
    blank()
    print(f"  {C_DIM}Your bid is cryptographically sealed. No one can read it before the deadline.{C_RESET}")
    blank()


# ─────────────────────────── My Bids ──────────────────────────────────────────

def cmd_my_bids(args: list[str]):
    """View all bids submitted by the current bidder."""
    session = _require_bidder()

    print_section_banner("My Submitted Bids", "📨")
    blank()

    procs   = ProcurementStore.list_all()
    my_bids = []

    for proc in procs:
        bids = BidStore.get_all_bids(proc["proc_id"])
        for b in bids:
            if b["bidder_username"] == session["username"]:
                my_bids.append((proc, b))

    if not my_bids:
        print_info("You have not submitted any bids yet.")
        blank()
        return

    for proc, bid in my_bids:
        print(f"  {C_BOLD}{bid['envelope_id']}{C_RESET}")
        print_key_value_block([
            ("Procurement",      proc["title"][:50]),
            ("Proc ID",          proc["proc_id"]),
            ("Submitted At",     bid["submitted_at"][:19].replace("T", " ") + " UTC"),
            ("Commitment Hash",  f"{bid['commitment_hash'][:24]}…"),
            ("Status",           proc["status"]),
        ])
        blank()
        divider()
        blank()

    print(f"  {C_DIM}Total bids: {len(my_bids)}{C_RESET}")
    blank()
