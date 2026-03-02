"""
CSePS Configuration & Constants
================================
Central configuration for all system parameters.
"""

import os

# ── Directory Layout ──────────────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
DATA_DIR     = os.path.join(BASE_DIR, "data")
KEYS_DIR     = os.path.join(DATA_DIR, "keys")
BIDS_DIR     = os.path.join(DATA_DIR, "bids")
REPORTS_DIR  = os.path.join(DATA_DIR, "reports")

# ── Ledger & Registry Files ───────────────────────────────────────────────────
LEDGER_FILE        = os.path.join(DATA_DIR, "audit_ledger.json")
USER_REGISTRY_FILE = os.path.join(DATA_DIR, "user_registry.json")
PROCUREMENT_FILE   = os.path.join(DATA_DIR, "procurements.json")
SESSION_FILE       = os.path.join(DATA_DIR, ".session")

# ── Cryptographic Parameters ──────────────────────────────────────────────────
ECC_CURVE        = "SECP384R1"     # NIST P-384 (~192-bit security)
AES_KEY_BYTES    = 32              # AES-256
GCM_NONCE_BYTES  = 12             # 96-bit GCM nonce
HKDF_INFO        = b"CSePS-procurement-v1"

# ── System Parameters ─────────────────────────────────────────────────────────
SYSTEM_VERSION   = "1.0.0"
SYSTEM_NAME      = "CSePS"
SYSTEM_FULL_NAME = "Cryptographically Secure Government e-Procurement System"
MIN_PASSWORD_LEN = 8

# ── Role Definitions ──────────────────────────────────────────────────────────
ROLE_AUTHORITY   = "authority"
ROLE_BIDDER      = "bidder"
ROLE_EVALUATOR   = "evaluator"
ALL_ROLES        = [ROLE_AUTHORITY, ROLE_BIDDER, ROLE_EVALUATOR]

# ── Procurement Status ────────────────────────────────────────────────────────
STATUS_OPEN      = "OPEN"
STATUS_CLOSED    = "CLOSED"
STATUS_EVALUATED = "EVALUATED"
STATUS_AWARDED   = "AWARDED"

# ── Colour codes (ANSI) ───────────────────────────────────────────────────────
C_RESET   = "\033[0m"
C_BOLD    = "\033[1m"
C_RED     = "\033[91m"
C_GREEN   = "\033[92m"
C_YELLOW  = "\033[93m"
C_BLUE    = "\033[94m"
C_MAGENTA = "\033[95m"
C_CYAN    = "\033[96m"
C_WHITE   = "\033[97m"
C_DIM     = "\033[2m"
C_HEADER  = "\033[95m\033[1m"
