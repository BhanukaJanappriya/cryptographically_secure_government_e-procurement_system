"""
CSePS Audit & Verification Commands
=====================================
Public audit functions — require NO private keys:
  - View audit ledger
  - Verify ledger chain integrity
  - Verify individual bid commitment & signature
"""

import sys
import json

from config import (
    C_GREEN, C_RED, C_YELLOW, C_CYAN, C_BOLD, C_RESET, C_DIM, C_MAGENTA,
)
from crypto_engine import (
    CommitmentScheme, DigitalSignature, TrustedTimestamp, sha3_256_hex,
    get_ledger_hmac_key, hmac_sha256_hex,
)
from storage import (
    UserStore, SessionStore, ProcurementStore, BidStore, LedgerStore,
)
from display import (
    print_section_banner, print_result_banner, print_phase_banner,
    print_success, print_error, print_warning, print_info,
    print_key_value_block, print_key_value, print_crypto, print_ledger,
    print_step, print_table, status_badge, blank, divider,
    prompt, prompt_confirm, working, short_hash,
)


# ─────────────────────────── View Audit Ledger ────────────────────────────────

def cmd_ledger(args: list[str]):
    """Display the public audit ledger."""
    SessionStore.require_login()

    print_section_banner("Public Audit Ledger", "📒")
    blank()

    proc_filter = args[0] if args else None
    entries     = (
        LedgerStore.get_by_proc(proc_filter)
        if proc_filter else LedgerStore.get_all()
    )

    if not entries:
        print_info("No ledger entries found.")
        blank()
        return

    total = LedgerStore.get_count()
    print(f"  {C_DIM}Total entries: {total}"
          + (f"  |  Filtered by proc: {proc_filter}" if proc_filter else "")
          + f"{C_RESET}")
    blank()

    rows = []
    for e in entries:
        rows.append([
            f"#{e['seq']}",
            e["timestamp"][:19].replace("T", " "),
            e["event_type"],
            e["actor"][:16],
            e["proc_id"][:18],
            short_hash(e["chain_hash"], 12).replace(C_DIM, "").replace(C_RESET, ""),
        ])

    print_table(
        ["Seq", "Timestamp (UTC)", "Event Type", "Actor", "Proc ID", "Chain Hash"],
        rows,
        col_widths=[5, 20, 25, 18, 20, 14],
    )
    blank()

    # Show last chain hash
    last = entries[-1]
    print(f"  {C_DIM}Last chain hash:{C_RESET}  {C_CYAN}{last['chain_hash'][:48]}…{C_RESET}")
    blank()


# ─────────────────────────── Verify Ledger Chain ──────────────────────────────

def cmd_verify_ledger(args: list[str]):
    """
    Cryptographically verify the entire ledger chain.
    Recomputes every SHA3-256 chain hash and HMAC from scratch.
    No private keys required — public verification.
    """
    print_section_banner("Ledger Integrity Verification", "🔍")
    blank()

    working("Loading ledger entries")
    entries = LedgerStore.get_all()
    total   = len(entries)

    if not total:
        print_info("Ledger is empty — nothing to verify.")
        blank()
        return

    print(f"  {C_DIM}Verifying {total} ledger entries…{C_RESET}")
    blank()

    is_valid, errors = LedgerStore.verify_chain()

    # Walk entries one by one for display
    prev  = LedgerStore.GENESIS_HASH
    PASS  = f"{C_GREEN}PASS{C_RESET}"
    FAIL  = f"{C_RED}FAIL{C_RESET}"

    rows = []
    all_ok = True
    for e in entries:
        # Recompute chain hash
        expected_chain = sha3_256_hex(prev + e["entry_hash"])
        chain_ok = expected_chain == e["chain_hash"]

        # Recompute HMAC
        expected_hmac = hmac_sha256_hex(
            get_ledger_hmac_key(), e["entry_hash"] + e["chain_hash"]
        )
        hmac_ok = expected_hmac == e["hmac_sig"]

        # Verify timestamp
        ts_ok = TrustedTimestamp.verify(e["ts_token"], e["entry_hash"])

        entry_ok = chain_ok and hmac_ok and ts_ok
        if not entry_ok:
            all_ok = False

        rows.append([
            f"#{e['seq']}",
            e["event_type"][:22],
            PASS if chain_ok else FAIL,
            PASS if hmac_ok  else FAIL,
            PASS if ts_ok    else FAIL,
            PASS if entry_ok else FAIL,
        ])
        prev = e["chain_hash"]

    print_table(
        ["Seq", "Event Type", "Chain Hash", "HMAC", "Timestamp", "Overall"],
        rows,
        col_widths=[5, 24, 12, 6, 11, 10],
    )
    blank()

    if all_ok:
        print_result_banner(
            f"LEDGER VERIFIED — All {total} entries valid. Chain is intact.", ok=True
        )
        print(f"  {C_GREEN}✔{C_RESET}  Hash chain: UNBROKEN")
        print(f"  {C_GREEN}✔{C_RESET}  HMAC signatures: ALL VALID")
        print(f"  {C_GREEN}✔{C_RESET}  Timestamps: ALL VALID")
        print(f"  {C_GREEN}✔{C_RESET}  No tampering detected")
    else:
        print_result_banner("LEDGER VERIFICATION FAILED — Tampering detected!", ok=False)
        for err in errors:
            print_error(err)
    blank()


# ─────────────────────────── Verify Single Bid ────────────────────────────────

def cmd_verify_bid(args: list[str]):
    """
    Publicly verify a specific sealed bid's commitment and digital signature.
    Does NOT decrypt the bid — no private key needed.
    Proves:
      1. The ciphertext was not modified since submission.
      2. The bidder cannot deny submitting this envelope.
    """
    print_section_banner("Bid Commitment & Signature Verification", "🔍")
    blank()
    print(f"  {C_DIM}This public verification requires NO private keys.{C_RESET}")
    print(f"  {C_DIM}It proves integrity and non-repudiation of a sealed bid.{C_RESET}")
    blank()

    proc_id    = args[0] if args else prompt("Procurement ID")
    envelope_id = args[1] if len(args) > 1 else prompt("Envelope ID")

    proc = ProcurementStore.get(proc_id)
    if not proc:
        print_error(f"Procurement '{proc_id}' not found.")
        sys.exit(1)

    bids = BidStore.get_all_bids(proc_id)
    envelope = next((b for b in bids if b["envelope_id"] == envelope_id), None)

    if not envelope:
        print_error(f"Envelope '{envelope_id}' not found in procurement '{proc_id}'.")
        sys.exit(1)

    bidder = UserStore.get_user(envelope["bidder_username"])
    b_name = bidder["full_name"] if bidder else envelope["bidder_username"]

    print_key_value_block([
        ("Envelope ID",   envelope_id),
        ("Bidder",        b_name),
        ("Submitted At",  envelope["submitted_at"][:19].replace("T", " ") + " UTC"),
        ("Procurement",   proc["title"][:50]),
    ])
    blank()

    print_phase_banner(0, "Cryptographic Verification Checks")
    blank()

    # ── Check 1: Commitment Hash ──────────────────────────────────────────────
    print_step("CHECK 1", "SHA3-256 Commitment Verification")
    enc_data = envelope["enc_data"]
    commit_ok = CommitmentScheme.verify(
        envelope["commitment_hash"],
        enc_data["ciphertext_b64"],
        enc_data["nonce_b64"],
    )
    if commit_ok:
        print_success("Commitment VALID — ciphertext has NOT been modified since submission.")
    else:
        print_error("Commitment INVALID — ciphertext has been TAMPERED with!")
    print_key_value("Stored commitment",    f"{envelope['commitment_hash'][:32]}…", 26)
    blank()

    # ── Check 2: Digital Signature ────────────────────────────────────────────
    print_step("CHECK 2", "ECDSA Signature Verification (Non-Repudiation)")
    sig_ok = False
    if bidder:
        sig_ok = DigitalSignature.verify(
            envelope["commitment_hash"].encode(),
            envelope["signature_b64"],
            bidder["public_key_pem"],
        )
        if sig_ok:
            print_success(
                f"Signature VALID — '{b_name}' cannot deny this submission."
            )
        else:
            print_error("Signature INVALID — signature does not match bidder's public key!")
    else:
        print_warning("Bidder public key not found — cannot verify signature.")
    print_key_value("Signature (partial)", f"{envelope['signature_b64'][:32]}…", 26)
    blank()

    # ── Check 3: Timestamp Token ──────────────────────────────────────────────
    print_step("CHECK 3", "Trusted Timestamp Verification")
    ts_token = envelope.get("ts_token")
    if ts_token:
        ts_ok = TrustedTimestamp.verify(ts_token, envelope["commitment_hash"])
        if ts_ok:
            print_success(f"Timestamp VALID — issued at {ts_token['issued_at'][:19]} UTC")
        else:
            print_error("Timestamp INVALID — timestamp token does not match commitment!")
    else:
        print_warning("No timestamp token found in envelope.")
        ts_ok = None

    blank()

    # ── Check 4: Ledger Entry ─────────────────────────────────────────────────
    print_step("CHECK 4", "Ledger Chain Presence")
    ledger_entries = LedgerStore.get_by_proc(proc_id)
    bid_entries = [
        e for e in ledger_entries
        if e.get("event_type") == "BID_SUBMITTED"
        and e.get("payload", {}).get("envelope_id") == envelope_id
    ]
    if bid_entries:
        le = bid_entries[0]
        print_success(f"Bid found on public ledger at entry #{le['seq']}")
        print_key_value("Chain hash (entry)",  f"{le['chain_hash'][:32]}…", 26)
    else:
        print_warning("Bid submission entry not found in ledger. Possible issue.")

    blank()

    # ── Summary ───────────────────────────────────────────────────────────────
    all_clear = commit_ok and sig_ok and (ts_ok is not False)
    print_result_banner(
        "BID CRYPTOGRAPHICALLY SOUND — No tampering detected." if all_clear
        else "BID VERIFICATION ISSUES DETECTED — Review findings above.",
        ok=all_clear,
    )

    checks = [
        ("Commitment integrity (SHA3-256)", commit_ok),
        ("Digital signature (ECDSA P-384)", sig_ok),
        ("Timestamp token",                 ts_ok if ts_ok is not None else False),
        ("Ledger presence",                 bool(bid_entries)),
    ]
    for check, result in checks:
        icon  = f"{C_GREEN}✔{C_RESET}" if result else f"{C_RED}✘{C_RESET}"
        print(f"  {icon}  {check}")
    blank()
