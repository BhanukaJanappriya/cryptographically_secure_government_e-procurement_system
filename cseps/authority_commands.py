"""
CSePS Authority Commands
=========================
Procurement authority actions:
  - Create / manage procurements
  - Close bidding
  - Open (decrypt) sealed bids after deadline
  - Award procurement
  - Run threshold key splitting ceremony
"""

import sys
import json
import secrets
from datetime import datetime, timezone

from config import (
    ROLE_AUTHORITY, STATUS_OPEN, STATUS_CLOSED, STATUS_AWARDED,
    C_GREEN, C_YELLOW, C_CYAN, C_BOLD, C_RESET, C_DIM, C_MAGENTA,
)
from crypto_engine import (
    KeyManager, CommitmentScheme, DigitalSignature, ThresholdKey,
)
from storage import (
    UserStore, SessionStore, ProcurementStore, BidStore, LedgerStore,
)
from display import (
    print_section_banner, print_result_banner, print_phase_banner,
    print_success, print_error, print_warning, print_info,
    print_key_value_block, print_key_value, print_crypto, print_ledger,
    print_step, print_table, role_badge, status_badge, blank, divider,
    prompt, prompt_password, prompt_float, prompt_int, prompt_confirm,
    working, short_hash,
)


def _require_authority() -> dict:
    return SessionStore.require_role(ROLE_AUTHORITY)


# ─────────────────────────── Create Procurement ───────────────────────────────

def cmd_new_procurement(args: list[str]):
    """Create a new procurement tender."""
    session = _require_authority()
    user    = UserStore.get_user(session["username"])

    print_section_banner("Create New Procurement Tender", "📋")
    blank()

    categories = [
        "Infrastructure & Construction",
        "IT & Software Services",
        "Medical & Healthcare",
        "Defence & Security",
        "Education & Training",
        "Transport & Logistics",
        "Energy & Utilities",
        "Professional Services",
    ]

    title       = prompt("Tender title")
    description = prompt("Tender description")
    print(f"\n  {C_DIM}Select category:{C_RESET}")
    category    = prompt("Category (press Enter to type custom)", required=False)
    if not category:
        category = input("  Custom category: ").strip()

    budget      = prompt_float("Estimated budget (USD)", min_val=1)
    deadline    = prompt("Submission deadline (YYYY-MM-DD HH:MM UTC)")

    # Generate unique procurement ID
    proc_id = f"PROC-{datetime.now(timezone.utc).strftime('%Y')}-" \
              f"{secrets.token_hex(3).upper()}"

    blank()
    print(f"  {C_DIM}Summary:{C_RESET}")
    print_key_value_block([
        ("Procurement ID", proc_id),
        ("Title",          title),
        ("Category",       category),
        ("Budget",         f"${budget:,.2f}"),
        ("Deadline",       deadline),
        ("Authority",      user["full_name"]),
    ])
    blank()

    if not prompt_confirm("Create this procurement?"):
        print_warning("Cancelled.")
        return

    working("Creating procurement record")
    ProcurementStore.create(
        proc_id=proc_id,
        title=title,
        description=description,
        category=category,
        budget=budget,
        deadline=deadline,
        authority_username=session["username"],
        authority_pub_pem=user["public_key_pem"],
    )

    working("Recording on audit ledger")
    entry = LedgerStore.append(
        event_type="PROCUREMENT_CREATED",
        actor=session["username"],
        proc_id=proc_id,
        payload={
            "title":    title,
            "category": category,
            "budget":   budget,
            "deadline": deadline,
        },
    )
    print_ledger(f"Ledger entry #{entry['seq']} | Chain: {short_hash(entry['chain_hash'])}")
    print_result_banner(f"Procurement '{proc_id}' created successfully!", ok=True)
    print(f"  {C_DIM}Bidders can now submit sealed bids for: {title}{C_RESET}")
    blank()


# ─────────────────────────── List Procurements ────────────────────────────────

def cmd_list_procurements(args: list[str]):
    """List all procurements (filtered by status if given)."""
    SessionStore.require_login()

    status_filter = args[0].upper() if args else None
    procs = ProcurementStore.list_all(status=status_filter)

    print_section_banner(
        f"Procurements{' [' + status_filter + ']' if status_filter else ''}",
        "📋"
    )
    blank()

    if not procs:
        print_info("No procurements found.")
        blank()
        return

    rows = []
    for p in procs:
        rows.append([
            p["proc_id"],
            p["title"][:32] + ("…" if len(p["title"]) > 32 else ""),
            p["category"][:20],
            f"${p['budget']:,.0f}",
            p["deadline"][:16],
            p["bid_count"],
            p["status"],
        ])

    print_table(
        ["Procurement ID", "Title", "Category", "Budget", "Deadline", "Bids", "Status"],
        rows,
        col_widths=[18, 34, 22, 12, 17, 4, 10],
    )
    blank()
    print(f"  {C_DIM}Total: {len(procs)} procurement(s){C_RESET}")
    blank()


# ─────────────────────────── Close Procurement ────────────────────────────────

def cmd_close_procurement(args: list[str]):
    """Close bidding on a procurement (no new bids accepted)."""
    session = _require_authority()

    print_section_banner("Close Procurement Bidding", "🔒")
    blank()

    proc_id = args[0] if args else prompt("Procurement ID")
    proc    = ProcurementStore.get(proc_id)

    if not proc:
        print_error(f"Procurement '{proc_id}' not found.")
        sys.exit(1)
    if proc["authority_username"] != session["username"]:
        print_error("You are not the authority for this procurement.")
        sys.exit(1)
    if proc["status"] != STATUS_OPEN:
        print_warning(f"Procurement is already {proc['status']}.")
        return

    print_key_value_block([
        ("Procurement ID", proc_id),
        ("Title",          proc["title"]),
        ("Bids received",  str(proc["bid_count"])),
        ("Current status", status_badge(proc["status"])),
    ])
    blank()

    if not prompt_confirm(f"Close bidding for '{proc_id}'?"):
        print_warning("Cancelled.")
        return

    ProcurementStore.update_status(proc_id, STATUS_CLOSED)

    entry = LedgerStore.append(
        event_type="PROCUREMENT_CLOSED",
        actor=session["username"],
        proc_id=proc_id,
        payload={"bid_count": proc["bid_count"]},
    )
    print_ledger(f"Ledger entry #{entry['seq']} | Chain: {short_hash(entry['chain_hash'])}")
    print_result_banner(f"Bidding closed for '{proc_id}'. No further bids accepted.", ok=True)
    blank()


# ─────────────────────────── Open (Decrypt) Bids ─────────────────────────────

def cmd_open_bids(args: list[str]):
    """Decrypt and reveal all sealed bids after the deadline."""
    session = _require_authority()

    print_section_banner("Open Sealed Bids — Deadline Ceremony", "🔓")
    blank()

    proc_id = args[0] if args else prompt("Procurement ID")
    proc    = ProcurementStore.get(proc_id)

    if not proc:
        print_error(f"Procurement '{proc_id}' not found.")
        sys.exit(1)
    if proc["authority_username"] != session["username"]:
        print_error("You are not the authority for this procurement.")
        sys.exit(1)
    if proc["status"] == STATUS_OPEN:
        print_error("Procurement must be CLOSED before opening bids.")
        print_info("Run: python main.py close-procurement first.")
        sys.exit(1)
    if proc["status"] == STATUS_AWARDED:
        print_warning("This procurement has already been awarded.")
        return

    sealed_bids = BidStore.get_all_bids(proc_id)
    if not sealed_bids:
        print_warning("No bids submitted for this procurement.")
        return

    print_key_value_block([
        ("Procurement ID", proc_id),
        ("Title",          proc["title"]),
        ("Bids to open",   str(len(sealed_bids))),
    ])
    blank()

    if not prompt_confirm("Proceed with opening all sealed bids? This is irreversible."):
        print_warning("Opening cancelled.")
        return

    # Load authority private key
    priv_pem = UserStore.load_private_key(session["username"])
    if not priv_pem:
        print_error("Authority private key not found. Cannot decrypt bids.")
        sys.exit(1)

    print_phase_banner(6, "Decrypting Sealed Bids")

    results = []
    for envelope in sealed_bids:
        env_id  = envelope["envelope_id"]
        bidder  = UserStore.get_user(envelope["bidder_username"])
        b_name  = bidder["full_name"] if bidder else envelope["bidder_username"]

        print_step("VERIFY", f"Checking commitment for {env_id} …")

        # 1. Verify commitment
        enc_data = envelope["enc_data"]
        if not CommitmentScheme.verify(
            envelope["commitment_hash"],
            enc_data["ciphertext_b64"],
            enc_data["nonce_b64"],
        ):
            print_error(f"  Commitment MISMATCH for {env_id} — BID TAMPERED, EXCLUDED.")
            LedgerStore.append(
                event_type="BID_TAMPER_DETECTED",
                actor=session["username"],
                proc_id=proc_id,
                payload={"envelope_id": env_id, "bidder": envelope["bidder_username"]},
            )
            continue

        # 2. Verify signature
        bidder_pub = bidder["public_key_pem"] if bidder else None
        if bidder_pub:
            sig_ok = DigitalSignature.verify(
                envelope["commitment_hash"].encode(),
                envelope["signature_b64"],
                bidder_pub,
            )
            sig_label = f"{C_GREEN}VALID{C_RESET}" if sig_ok else f"{C_YELLOW}WARN{C_RESET}"
            print_step("SIGN ", f"Signature check for '{b_name}': {sig_label}")

        # 3. Decrypt
        try:
            from crypto_engine import HybridEncryption
            plaintext = HybridEncryption.decrypt(enc_data, priv_pem)
            payload   = json.loads(plaintext.decode())
            results.append({
                "envelope_id":   env_id,
                "bidder":        b_name,
                "bidder_user":   envelope["bidder_username"],
                "company":       payload.get("company_reg", "N/A"),
                "unit_price":    payload.get("unit_price", 0),
                "total_amount":  payload.get("total_amount", 0),
                "delivery_days": payload.get("delivery_days", 0),
                "notes":         payload.get("notes", ""),
            })
            print_step("OPEN ", f"'{b_name}'  →  ${payload.get('total_amount', 0):,.2f}")

            LedgerStore.append(
                event_type="BID_DECRYPTED",
                actor=session["username"],
                proc_id=proc_id,
                payload={
                    "envelope_id": env_id,
                    "bidder":      envelope["bidder_username"],
                    "total_amount": payload.get("total_amount"),
                },
            )
        except Exception as ex:
            print_error(f"  Decryption failed for {env_id}: {ex}")

    if not results:
        print_error("No valid bids could be decrypted.")
        return

    # Sort by total amount
    results.sort(key=lambda r: r["total_amount"])

    print_phase_banner(7, "Bid Evaluation Results")

    rows = []
    for rank, r in enumerate(results, 1):
        medal = {1: "🥇", 2: "🥈", 3: "🥉"}.get(rank, f"#{rank}")
        rows.append([
            medal,
            r["bidder"][:28],
            r["company"],
            f"${r['unit_price']:,.2f}",
            f"${r['total_amount']:,.2f}",
            f"{r['delivery_days']}d",
            r["envelope_id"][:14] + "…",
        ])

    print_table(
        ["", "Bidder", "Company Reg", "Unit Price", "Total Amount", "Delivery", "Envelope"],
        rows,
        col_widths=[3, 30, 14, 12, 13, 8, 16],
    )
    blank()

    winner = results[0]
    print(f"  {C_BOLD}Recommended Winner:{C_RESET}  "
          f"{C_GREEN}{winner['bidder']}{C_RESET}  "
          f"— ${winner['total_amount']:,.2f}")

    # Persist results alongside sealed bids for evaluator access
    import os
    from config import REPORTS_DIR
    report_path = os.path.join(REPORTS_DIR, f"{proc_id}_opened.json")
    with open(report_path, "w") as f:
        json.dump({"proc_id": proc_id, "results": results}, f, indent=2)

    ProcurementStore.update_status(proc_id, "EVALUATED")
    entry = LedgerStore.append(
        event_type="BIDS_OPENED",
        actor=session["username"],
        proc_id=proc_id,
        payload={"bid_count": len(results), "lowest_bid": results[0]["total_amount"]},
    )
    print_ledger(f"Ledger entry #{entry['seq']} | Chain: {short_hash(entry['chain_hash'])}")
    blank()
    print(f"  {C_DIM}Evaluators can now run: python main.py view-bids {proc_id}{C_RESET}")
    blank()


# ─────────────────────────── Award Procurement ────────────────────────────────

def cmd_award(args: list[str]):
    """Award the procurement to the winning bidder."""
    session = _require_authority()

    print_section_banner("Award Procurement", "🏆")
    blank()

    proc_id = args[0] if args else prompt("Procurement ID")
    proc    = ProcurementStore.get(proc_id)

    if not proc:
        print_error(f"Procurement '{proc_id}' not found.")
        sys.exit(1)
    if proc["authority_username"] != session["username"]:
        print_error("You are not the authority for this procurement.")
        sys.exit(1)
    if proc["status"] not in ("EVALUATED", "CLOSED"):
        print_error(f"Procurement must be EVALUATED before awarding (current: {proc['status']}).")
        sys.exit(1)

    winner  = prompt("Winner username")
    notes   = prompt("Award justification / notes", required=False)

    if not prompt_confirm(f"Award '{proc_id}' to '{winner}'?"):
        print_warning("Cancelled.")
        return

    ProcurementStore.set_winner(proc_id, winner, notes)

    entry = LedgerStore.append(
        event_type="PROCUREMENT_AWARDED",
        actor=session["username"],
        proc_id=proc_id,
        payload={"winner": winner, "notes": notes},
    )
    print_ledger(f"Ledger entry #{entry['seq']} | Chain: {short_hash(entry['chain_hash'])}")
    print_result_banner(f"Procurement '{proc_id}' awarded to '{winner}'!", ok=True)
    blank()


# ─────────────────────────── Key Ceremony ─────────────────────────────────────

def cmd_key_ceremony(args: list[str]):
    """
    Threshold key splitting ceremony.
    Splits the authority's private key into N shares held by N officials.
    All N shares required to reconstruct (n-of-n).
    """
    session = _require_authority()

    print_section_banner("Threshold Key Splitting Ceremony", "🔑")
    blank()
    print(f"  {C_DIM}This ceremony splits the authority decryption key into multiple shares.{C_RESET}")
    print(f"  {C_DIM}All share-holders must cooperate to reconstruct the key.{C_RESET}")
    blank()

    n = prompt_int("Number of key shares (officers)", min_val=2)
    blank()

    priv_pem = UserStore.load_private_key(session["username"])
    if not priv_pem:
        print_error("Private key not found.")
        sys.exit(1)

    priv_bytes = KeyManager.load_private_key(priv_pem).private_bytes(
        __import__('cryptography').hazmat.primitives.serialization.Encoding.Raw,
        __import__('cryptography').hazmat.primitives.serialization.PrivateFormat.Raw,
        __import__('cryptography').hazmat.primitives.serialization.NoEncryption(),
    )[:32]

    working(f"Splitting key into {n} shares")
    shares = ThresholdKey.split(priv_bytes, n)

    print_phase_banner(0, f"Key Shares — Distribute ONE share to each officer")
    blank()
    for i, share in enumerate(shares, 1):
        officer = prompt(f"Officer {i} name / username")
        print_key_value(f"Officer {i} ({officer}) Share", share.hex())
        print_crypto(f"Share {i}: {share.hex()[:32]}…{share.hex()[-8:]}")
        blank()

    # Verify reconstruction works
    reconstructed = ThresholdKey.reconstruct(shares)
    ok = reconstructed == priv_bytes
    if ok:
        print_success("Reconstruction verification: PASSED ✓")
    else:
        print_error("Reconstruction verification: FAILED — contact system administrator!")

    entry = LedgerStore.append(
        event_type="KEY_CEREMONY",
        actor=session["username"],
        proc_id="SYSTEM",
        payload={"share_count": n, "verification": ok},
    )
    print_ledger(f"Ceremony recorded on ledger: entry #{entry['seq']}")
    blank()
    print(f"  {C_DIM}IMPORTANT: Each officer must store their share securely (e.g. USB in a safe).{C_RESET}")
    print(f"  {C_DIM}No single officer can open bids without all others.{C_RESET}")
    blank()
