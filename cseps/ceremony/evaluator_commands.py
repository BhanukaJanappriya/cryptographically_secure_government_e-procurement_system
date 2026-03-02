"""
CSePS Evaluator Commands
=========================
Evaluator actions:
  - View opened (decrypted) bids
  - Submit evaluation recommendation
  - View procurement details
"""

import sys
import os
import json

from config import (
    ROLE_EVALUATOR, REPORTS_DIR,
    C_GREEN, C_YELLOW, C_CYAN, C_BOLD, C_RESET, C_DIM,
)
from storage import (
    UserStore, SessionStore, ProcurementStore, BidStore, LedgerStore,
)
from display import (
    print_section_banner, print_result_banner, print_phase_banner,
    print_success, print_error, print_warning, print_info,
    print_key_value_block, print_key_value, print_ledger,
    print_step, print_table, prompt_float, prompt_int, status_badge, blank, divider,
    prompt, prompt_confirm, working, short_hash,
)


def _require_evaluator() -> dict:
    return SessionStore.require_role(ROLE_EVALUATOR)


# ─────────────────────────── View Opened Bids ─────────────────────────────────

def cmd_view_bids(args: list[str]):
    """
    View the decrypted bid results for an evaluated procurement.
    Only available after the authority has run open-bids.
    """
    session = _require_evaluator()

    print_section_banner("View Opened Bid Results", "📊")
    blank()

    proc_id = args[0] if args else prompt("Procurement ID")
    proc    = ProcurementStore.get(proc_id)

    if not proc:
        print_error(f"Procurement '{proc_id}' not found.")
        sys.exit(1)

    if proc["status"] not in ("EVALUATED", "AWARDED"):
        print_error(
            f"Bids for '{proc_id}' have not been opened yet.\n"
            f"  Current status: {proc['status']}\n"
            f"  Authority must run: python main.py open-bids {proc_id}"
        )
        sys.exit(1)

    # Load the opened results report
    report_path = os.path.join(REPORTS_DIR, f"{proc_id}_opened.json")
    if not os.path.exists(report_path):
        print_error("Opened bid report not found. Contact the procurement authority.")
        sys.exit(1)

    with open(report_path, "r") as f:
        report = json.load(f)

    results = report.get("results", [])

    print(f"  {C_BOLD}Procurement:{C_RESET} {proc['title']}")
    print_key_value_block([
        ("ID",       proc_id),
        ("Category", proc["category"]),
        ("Budget",   f"${proc['budget']:,.2f}"),
        ("Status",   status_badge(proc["status"])),
    ])
    blank()

    if not results:
        print_warning("No bid results available.")
        return

    # Table view
    rows = []
    for rank, r in enumerate(results, 1):
        medal = {1: "🥇", 2: "🥈", 3: "🥉"}.get(rank, f" #{rank}")
        rows.append([
            medal,
            r["bidder"][:26],
            r["company"],
            f"${r['unit_price']:,.2f}",
            f"${r['total_amount']:,.2f}",
            f"{r['delivery_days']}d",
            r.get("notes", "")[:20],
        ])

    print_table(
        ["", "Bidder", "Company Reg", "Unit Price", "Total", "Delivery", "Notes"],
        rows,
        col_widths=[3, 28, 14, 12, 13, 8, 22],
    )
    blank()

    best = results[0]
    print(f"  {C_BOLD}Lowest bid:{C_RESET}  "
          f"{C_GREEN}{best['bidder']}{C_RESET}  "
          f"— ${best['total_amount']:,.2f}  ({best['delivery_days']} days)")
    blank()

    if proc["status"] == "AWARDED":
        print(f"  {C_BOLD}Awarded to:{C_RESET}  "
              f"{C_GREEN}{proc['winner']}{C_RESET}")
        if proc["evaluation_notes"]:
            print(f"  {C_DIM}Notes: {proc['evaluation_notes']}{C_RESET}")
        blank()


# ─────────────────────────── Submit Evaluation ────────────────────────────────

def cmd_evaluate(args: list[str]):
    """Submit an evaluation recommendation for a procurement."""
    session = _require_evaluator()
    user    = UserStore.get_user(session["username"])

    print_section_banner("Submit Evaluation Recommendation", "📝")
    blank()

    proc_id = args[0] if args else prompt("Procurement ID")
    proc    = ProcurementStore.get(proc_id)

    if not proc:
        print_error(f"Procurement '{proc_id}' not found.")
        sys.exit(1)
    if proc["status"] not in ("EVALUATED", "CLOSED"):
        print_error(f"Procurement must be EVALUATED to submit a recommendation.")
        sys.exit(1)

    report_path = os.path.join(REPORTS_DIR, f"{proc_id}_opened.json")
    if not os.path.exists(report_path):
        print_error("Bid results not yet available. Authority must open bids first.")
        sys.exit(1)

    with open(report_path, "r") as f:
        report = json.load(f)

    results = report.get("results", [])
    if not results:
        print_warning("No bid results to evaluate.")
        return

    print(f"  {C_DIM}Available bidders:{C_RESET}")
    for i, r in enumerate(results, 1):
        print(f"    {i}. {r['bidder']} — ${r['total_amount']:,.2f} ({r['delivery_days']} days)")
    blank()

    recommended = prompt("Recommended winner (username or full name)")
    score       = prompt_int("Technical score (1-100)", min_val=1)
    financial   = prompt_float("Financial score weight (%)", min_val=0)
    notes       = prompt("Evaluation notes / justification")

    if not prompt_confirm("Submit this evaluation recommendation?"):
        print_warning("Evaluation cancelled.")
        return

    # Save evaluation report
    eval_path = os.path.join(REPORTS_DIR, f"{proc_id}_eval_{session['username']}.json")
    eval_data = {
        "proc_id":       proc_id,
        "evaluator":     session["username"],
        "evaluator_name": user["full_name"],
        "recommended":   recommended,
        "tech_score":    score,
        "financial_weight": financial,
        "notes":         notes,
    }
    with open(eval_path, "w") as f:
        json.dump(eval_data, f, indent=2)

    entry = LedgerStore.append(
        event_type="EVALUATION_SUBMITTED",
        actor=session["username"],
        proc_id=proc_id,
        payload={
            "evaluator":   session["username"],
            "recommended": recommended,
            "tech_score":  score,
            "notes":       notes,
        },
    )
    print_ledger(f"Ledger entry #{entry['seq']} | Chain: {short_hash(entry['chain_hash'])}")
    print_result_banner("Evaluation recommendation submitted.", ok=True)
    print_key_value_block([
        ("Procurement",   proc_id),
        ("Recommended",   recommended),
        ("Tech Score",    str(score)),
        ("Notes",         notes[:60]),
        ("Ledger Entry",  f"#{entry['seq']}"),
    ])
    blank()
    print(f"  {C_DIM}The authority can now run: python main.py award {proc_id}{C_RESET}")
    blank()
