"""
CSePS CLI Display Utilities
============================
Terminal UI helpers: banners, tables, prompts, status indicators.
"""

import os
import sys
import getpass
from datetime import datetime

from config import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_BLUE,
    C_MAGENTA, C_CYAN, C_WHITE, C_DIM, C_HEADER,
    SYSTEM_NAME, SYSTEM_FULL_NAME, SYSTEM_VERSION,
    ROLE_AUTHORITY, ROLE_BIDDER, ROLE_EVALUATOR,
)


# ── Terminal width helper ─────────────────────────────────────────────────────

def term_width() -> int:
    try:
        return os.get_terminal_size().columns
    except Exception:
        return 80


# ── Basic output helpers ──────────────────────────────────────────────────────

def print_success(msg: str):
    print(f"  {C_GREEN}✔  {msg}{C_RESET}")

def print_error(msg: str):
    print(f"  {C_RED}✘  {msg}{C_RESET}")

def print_warning(msg: str):
    print(f"  {C_YELLOW}⚠  {msg}{C_RESET}")

def print_info(msg: str):
    print(f"  {C_CYAN}ℹ  {msg}{C_RESET}")

def print_step(step: str, msg: str):
    print(f"  {C_DIM}[{step}]{C_RESET} {msg}")

def print_crypto(msg: str):
    print(f"  {C_MAGENTA}🔐 {msg}{C_RESET}")

def print_ledger(msg: str):
    print(f"  {C_BLUE}📒 {msg}{C_RESET}")

def divider(char: str = "─", color: str = C_DIM):
    w = min(term_width(), 80)
    print(f"{color}{char * w}{C_RESET}")

def blank():
    print()


# ── Banners ───────────────────────────────────────────────────────────────────

def print_main_banner():
    w = 72
    print()
    print(f"{C_CYAN}{'═' * w}{C_RESET}")
    print(f"{C_CYAN}║{C_RESET}{C_BOLD}{'':^70}{C_RESET}{C_CYAN}║{C_RESET}")
    title = f"⚖  {SYSTEM_NAME}  —  {SYSTEM_FULL_NAME}"
    print(f"{C_CYAN}║{C_RESET}{C_BOLD}{C_WHITE}{title:^70}{C_RESET}{C_CYAN}║{C_RESET}")
    sub   = f"Government Procurement Security Platform  v{SYSTEM_VERSION}"
    print(f"{C_CYAN}║{C_RESET}{C_DIM}{sub:^70}{C_RESET}{C_CYAN}║{C_RESET}")
    print(f"{C_CYAN}║{C_RESET}{C_DIM}{'ECC P-384 · ECDSA · AES-256-GCM · SHA3-256 · Hash Chain':^70}{C_RESET}{C_CYAN}║{C_RESET}")
    print(f"{C_CYAN}║{C_RESET}{C_DIM}{'':^70}{C_RESET}{C_CYAN}║{C_RESET}")
    print(f"{C_CYAN}{'═' * w}{C_RESET}")
    print()


def print_section_banner(title: str, icon: str = "▶"):
    w = 72
    blank()
    print(f"{C_BLUE}{'─' * w}{C_RESET}")
    print(f"{C_BLUE}{icon}{C_RESET}  {C_BOLD}{C_WHITE}{title}{C_RESET}")
    print(f"{C_BLUE}{'─' * w}{C_RESET}")


def print_phase_banner(phase: int, title: str):
    w = 72
    blank()
    print(f"{C_MAGENTA}{'═' * w}{C_RESET}")
    print(f"{C_MAGENTA}  PHASE {phase}{C_RESET}  {C_BOLD}{title}{C_RESET}")
    print(f"{C_MAGENTA}{'═' * w}{C_RESET}")


def print_result_banner(msg: str, ok: bool = True):
    color = C_GREEN if ok else C_RED
    icon  = "✔" if ok else "✘"
    w     = 72
    blank()
    print(f"{color}{'─' * w}{C_RESET}")
    print(f"{color}  {icon}  {C_BOLD}{msg}{C_RESET}")
    print(f"{color}{'─' * w}{C_RESET}")
    blank()


# ── Tables ────────────────────────────────────────────────────────────────────

def print_table(headers: list[str], rows: list[list], col_widths: list[int] = None):
    """Print a formatted ASCII table."""
    n = len(headers)
    if col_widths is None:
        col_widths = []
        for i, h in enumerate(headers):
            max_w = len(h)
            for row in rows:
                if i < len(row):
                    max_w = max(max_w, len(str(row[i])))
            col_widths.append(min(max_w + 2, 40))

    sep = "  " + "┼".join("─" * (w + 2) for w in col_widths)
    header_row = "  " + "│".join(
        f" {C_BOLD}{C_WHITE}{h:<{col_widths[i]}}{C_RESET} "
        for i, h in enumerate(headers)
    )
    top = "  " + "┬".join("─" * (w + 2) for w in col_widths)
    bot = "  " + "┴".join("─" * (w + 2) for w in col_widths)

    print(f"{C_DIM}{top}{C_RESET}")
    print(header_row)
    print(f"{C_DIM}{sep}{C_RESET}")
    for row in rows:
        cells = []
        for i, h in enumerate(headers):
            val = str(row[i]) if i < len(row) else ""
            cells.append(f" {val:<{col_widths[i]}} ")
        print("  " + "│".join(cells))
    print(f"{C_DIM}{bot}{C_RESET}")


def print_key_value(label: str, value: str, label_w: int = 24):
    pad_label = f"{label}:"
    print(f"  {C_DIM}{pad_label:<{label_w}}{C_RESET}  {value}")


def print_key_value_block(items: list[tuple[str, str]], label_w: int = 24):
    for label, value in items:
        print_key_value(label, value, label_w)


# ── Role badge ────────────────────────────────────────────────────────────────

ROLE_COLORS = {
    ROLE_AUTHORITY: C_YELLOW,
    ROLE_BIDDER:    C_CYAN,
    ROLE_EVALUATOR: C_GREEN,
}

def role_badge(role: str) -> str:
    color = ROLE_COLORS.get(role, C_WHITE)
    return f"{color}[{role.upper()}]{C_RESET}"


def status_badge(status: str) -> str:
    colors = {
        "OPEN":      C_GREEN,
        "CLOSED":    C_YELLOW,
        "EVALUATED": C_BLUE,
        "AWARDED":   C_MAGENTA,
        "VALID":     C_GREEN,
        "INVALID":   C_RED,
        "TAMPERED":  C_RED,
    }
    color = colors.get(status, C_WHITE)
    return f"{color}[{status}]{C_RESET}"


# ── Input prompts ─────────────────────────────────────────────────────────────

def prompt(label: str, default: str = None, required: bool = True) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        val = input(f"  {C_CYAN}▸{C_RESET} {label}{suffix}: ").strip()
        if not val and default:
            return default
        if val or not required:
            return val
        print_error("This field is required.")


def prompt_password(label: str = "Password") -> str:
    while True:
        val = getpass.getpass(f"  {C_CYAN}▸{C_RESET} {label}: ")
        if val:
            return val
        print_error("Password cannot be empty.")


def prompt_confirm(msg: str, default: bool = False) -> bool:
    hint = "[Y/n]" if default else "[y/N]"
    val  = input(f"  {C_YELLOW}?{C_RESET}  {msg} {hint}: ").strip().lower()
    if not val:
        return default
    return val in ("y", "yes")


def prompt_float(label: str, min_val: float = 0) -> float:
    while True:
        try:
            val = float(input(f"  {C_CYAN}▸{C_RESET} {label}: ").strip())
            if val >= min_val:
                return val
            print_error(f"Value must be ≥ {min_val}")
        except ValueError:
            print_error("Please enter a valid number.")


def prompt_int(label: str, min_val: int = 1) -> int:
    while True:
        try:
            val = int(input(f"  {C_CYAN}▸{C_RESET} {label}: ").strip())
            if val >= min_val:
                return val
            print_error(f"Value must be ≥ {min_val}")
        except ValueError:
            print_error("Please enter a valid integer.")


def prompt_choice(label: str, choices: list[str]) -> str:
    for i, c in enumerate(choices, 1):
        print(f"    {C_DIM}{i}.{C_RESET} {c}")
    while True:
        val = input(f"  {C_CYAN}▸{C_RESET} {label} (1-{len(choices)}): ").strip()
        try:
            idx = int(val) - 1
            if 0 <= idx < len(choices):
                return choices[idx]
        except ValueError:
            pass
        print_error(f"Enter a number between 1 and {len(choices)}")


# ── Hash display helpers ──────────────────────────────────────────────────────

def short_hash(h: str, n: int = 16) -> str:
    return f"{C_DIM}{h[:n]}…{C_RESET}"


def print_hash_line(label: str, h: str):
    print(f"  {C_DIM}{label}:{C_RESET}  {C_CYAN}{h[:32]}…{C_RESET}")


# ── Loading spinner (simple) ──────────────────────────────────────────────────

def working(msg: str):
    print(f"  {C_DIM}⏳ {msg}…{C_RESET}")


# ── Usage help ────────────────────────────────────────────────────────────────

def print_usage():
    print_main_banner()
    sections = [
        ("Authentication", [
            ("register",    "Register a new account (bidder/evaluator/authority)"),
            ("login",       "Login to your account"),
            ("logout",      "End current session"),
            ("whoami",      "Show current logged-in user"),
        ]),
        ("Authority Commands", [
            ("new-procurement",    "Create a new procurement tender"),
            ("list-procurements",  "List all procurements"),
            ("close-procurement",  "Close bidding on a procurement"),
            ("open-bids",          "Decrypt & reveal all sealed bids (post-deadline)"),
            ("award",              "Award procurement to winning bidder"),
            ("key-ceremony",       "Run threshold key splitting ceremony"),
        ]),
        ("Bidder Commands", [
            ("list-procurements",  "Browse open procurements"),
            ("submit-bid",         "Submit a sealed encrypted bid"),
            ("my-bids",            "View your submitted bid envelopes"),
        ]),
        ("Evaluator Commands", [
            ("list-procurements",  "List all procurements"),
            ("view-bids",          "View opened (decrypted) bids for evaluation"),
            ("evaluate",           "Submit evaluation recommendation"),
        ]),
        ("Audit & Verification", [
            ("ledger",             "View the public audit ledger"),
            ("verify-ledger",      "Cryptographically verify ledger integrity"),
            ("verify-bid",         "Verify a specific bid commitment & signature"),
        ]),
    ]

    for section, cmds in sections:
        blank()
        print(f"  {C_BOLD}{C_WHITE}{section}{C_RESET}")
        divider()
        for cmd, desc in cmds:
            print(f"    {C_CYAN}cseps {cmd:<22}{C_RESET}  {C_DIM}{desc}{C_RESET}")

    blank()
    print(f"  {C_DIM}Usage: python main.py <command> [options]{C_RESET}")
    blank()
