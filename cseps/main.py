#!/usr/bin/env python3
"""
CSePS — Cryptographically Secure Government e-Procurement System
================================================================
Main CLI entry point.

Usage:
    python main.py <command> [args...]
    python main.py help

Examples:
    python main.py register
    python main.py login
    python main.py new-procurement
    python main.py submit-bid PROC-2024-ABC123
    python main.py verify-ledger
    python main.py verify-bid PROC-2024-ABC123 ENV-AABBCC112233
"""

import sys
import os

# ── Bootstrap data directories ────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from storage import bootstrap_dirs
bootstrap_dirs()

from display import print_main_banner, print_usage, print_error, blank
from config  import C_RESET, C_DIM


# ── Command registry ──────────────────────────────────────────────────────────

def build_commands():
    # Lazy imports to keep startup fast
    from auth_commands      import cmd_register, cmd_login, cmd_logout, cmd_whoami
    from authority_commands import (
        cmd_new_procurement, cmd_list_procurements,
        cmd_close_procurement, cmd_open_bids, cmd_award, cmd_key_ceremony,
    )
    from ceremony.bidder_commands    import cmd_submit_bid, cmd_my_bids
    from ceremony.evaluator_commands import cmd_view_bids, cmd_evaluate
    from ceremony.audit_commands     import cmd_ledger, cmd_verify_ledger, cmd_verify_bid

    return {
        # ── Auth ──────────────────────────────────────────────────────────────
        "register":           cmd_register,
        "login":              cmd_login,
        "logout":             cmd_logout,
        "whoami":             cmd_whoami,
        # ── Authority ─────────────────────────────────────────────────────────
        "new-procurement":    cmd_new_procurement,
        "list-procurements":  cmd_list_procurements,
        "close-procurement":  cmd_close_procurement,
        "open-bids":          cmd_open_bids,
        "award":              cmd_award,
        "key-ceremony":       cmd_key_ceremony,
        # ── Bidder ────────────────────────────────────────────────────────────
        "submit-bid":         cmd_submit_bid,
        "my-bids":            cmd_my_bids,
        # ── Evaluator ─────────────────────────────────────────────────────────
        "view-bids":          cmd_view_bids,
        "evaluate":           cmd_evaluate,
        # ── Audit / Verification ──────────────────────────────────────────────
        "ledger":             cmd_ledger,
        "verify-ledger":      cmd_verify_ledger,
        "verify-bid":         cmd_verify_bid,
        # ── Help aliases ──────────────────────────────────────────────────────
        "help":               lambda _: print_usage(),
        "--help":             lambda _: print_usage(),
        "-h":                 lambda _: print_usage(),
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print_main_banner()
        print_usage()
        sys.exit(0)

    command = sys.argv[1].lower()
    args    = sys.argv[2:]

    commands = build_commands()

    if command not in commands:
        print_main_banner()
        print_error(f"Unknown command: '{command}'")
        blank()
        print(f"  {C_DIM}Run 'python main.py help' to see all available commands.{C_RESET}")
        blank()
        sys.exit(1)

    try:
        commands[command](args)
    except PermissionError as e:
        print_error(str(e))
        blank()
        sys.exit(1)
    except KeyboardInterrupt:
        blank()
        print(f"  {C_DIM}Interrupted.{C_RESET}")
        blank()
        sys.exit(0)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        if "--debug" in sys.argv or os.getenv("CSEPS_DEBUG"):
            import traceback
            traceback.print_exc()
        blank()
        sys.exit(1)


if __name__ == "__main__":
    main()
