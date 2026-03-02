"""
CSePS Storage Layer
====================
JSON-based persistence for:
  - User registry (hashed passwords, public keys, roles)
  - Procurement registry (metadata, status)
  - Sealed bid envelopes (per procurement)
  - Append-only hash-chained audit ledger
  - Active session token
"""

import os
import json
import hashlib
import hmac
import secrets
from datetime import datetime, timezone

from config import (
    DATA_DIR, KEYS_DIR, BIDS_DIR, REPORTS_DIR,
    LEDGER_FILE, USER_REGISTRY_FILE, PROCUREMENT_FILE, SESSION_FILE,
)
from crypto_engine import (
    sha3_256_hex, hmac_sha256_hex, get_ledger_hmac_key, TrustedTimestamp
)


# ── Bootstrap directory structure ─────────────────────────────────────────────

def bootstrap_dirs():
    for d in [DATA_DIR, KEYS_DIR, BIDS_DIR, REPORTS_DIR]:
        os.makedirs(d, exist_ok=True)

    if not os.path.exists(LEDGER_FILE):
        _write_json(LEDGER_FILE, {"genesis": "0" * 64, "entries": []})

    if not os.path.exists(USER_REGISTRY_FILE):
        _write_json(USER_REGISTRY_FILE, {"users": {}})

    if not os.path.exists(PROCUREMENT_FILE):
        _write_json(PROCUREMENT_FILE, {"procurements": {}})


# ── Low-level JSON helpers ─────────────────────────────────────────────────────

def _read_json(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)


def _write_json(path: str, data: dict):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


# ─────────────────────────── User Registry ────────────────────────────────────

class UserStore:
    """
    Persists user accounts: username, role, hashed password, public key.
    Passwords are stored as SHA3-256(salt + password) — not plaintext.
    """

    @staticmethod
    def _load() -> dict:
        return _read_json(USER_REGISTRY_FILE)

    @staticmethod
    def _save(data: dict):
        _write_json(USER_REGISTRY_FILE, data)

    @classmethod
    def user_exists(cls, username: str) -> bool:
        return username in cls._load()["users"]

    @classmethod
    def register(cls, username: str, password: str, role: str,
                 full_name: str, organisation: str,
                 public_key_pem: str) -> bool:
        data = cls._load()
        if username in data["users"]:
            return False

        salt = secrets.token_hex(16)
        pw_hash = hashlib.sha3_256((salt + password).encode()).hexdigest()

        data["users"][username] = {
            "username":     username,
            "full_name":    full_name,
            "organisation": organisation,
            "role":         role,
            "salt":         salt,
            "pw_hash":      pw_hash,
            "public_key_pem": public_key_pem,
            "registered_at":  datetime.now(timezone.utc).isoformat(),
            "active":       True,
        }
        cls._save(data)
        return True

    @classmethod
    def authenticate(cls, username: str, password: str) -> dict | None:
        data = cls._load()
        user = data["users"].get(username)
        if not user:
            return None
        expected = hashlib.sha3_256((user["salt"] + password).encode()).hexdigest()
        if hmac.compare_digest(expected, user["pw_hash"]):
            return user
        return None

    @classmethod
    def get_user(cls, username: str) -> dict | None:
        return cls._load()["users"].get(username)

    @classmethod
    def list_users(cls, role: str = None) -> list[dict]:
        users = cls._load()["users"].values()
        if role:
            users = [u for u in users if u["role"] == role]
        return list(users)

    @classmethod
    def save_private_key(cls, username: str, private_key_pem: str):
        """Store private key in keys/ directory, named by username."""
        path = os.path.join(KEYS_DIR, f"{username}.pem")
        with open(path, "w") as f:
            f.write(private_key_pem)
        os.chmod(path, 0o600)

    @classmethod
    def load_private_key(cls, username: str) -> str | None:
        path = os.path.join(KEYS_DIR, f"{username}.pem")
        if not os.path.exists(path):
            return None
        with open(path, "r") as f:
            return f.read()


# ─────────────────────────── Procurement Store ────────────────────────────────

class ProcurementStore:
    """Persists procurement records and metadata."""

    @staticmethod
    def _load() -> dict:
        return _read_json(PROCUREMENT_FILE)

    @staticmethod
    def _save(data: dict):
        _write_json(PROCUREMENT_FILE, data)

    @classmethod
    def create(cls, proc_id: str, title: str, description: str,
               category: str, budget: float, deadline: str,
               authority_username: str, authority_pub_pem: str) -> bool:
        data = cls._load()
        if proc_id in data["procurements"]:
            return False

        data["procurements"][proc_id] = {
            "proc_id":            proc_id,
            "title":              title,
            "description":        description,
            "category":           category,
            "budget":             budget,
            "deadline":           deadline,
            "authority_username": authority_username,
            "authority_pub_pem":  authority_pub_pem,
            "status":             "OPEN",
            "created_at":         datetime.now(timezone.utc).isoformat(),
            "bid_count":          0,
            "winner":             None,
            "evaluation_notes":   None,
        }
        cls._save(data)
        return True

    @classmethod
    def get(cls, proc_id: str) -> dict | None:
        return cls._load()["procurements"].get(proc_id)

    @classmethod
    def list_all(cls, status: str = None) -> list[dict]:
        procs = cls._load()["procurements"].values()
        if status:
            procs = [p for p in procs if p["status"] == status]
        return list(procs)

    @classmethod
    def update_status(cls, proc_id: str, status: str):
        data = cls._load()
        if proc_id in data["procurements"]:
            data["procurements"][proc_id]["status"] = status
            cls._save(data)

    @classmethod
    def increment_bid_count(cls, proc_id: str):
        data = cls._load()
        if proc_id in data["procurements"]:
            data["procurements"][proc_id]["bid_count"] += 1
            cls._save(data)

    @classmethod
    def set_winner(cls, proc_id: str, winner: str, notes: str):
        data = cls._load()
        if proc_id in data["procurements"]:
            data["procurements"][proc_id]["winner"]           = winner
            data["procurements"][proc_id]["evaluation_notes"] = notes
            data["procurements"][proc_id]["status"]           = "AWARDED"
            cls._save(data)


# ─────────────────────────── Bid Store ────────────────────────────────────────

class BidStore:
    """
    Persists sealed bid envelopes per procurement.
    Each procurement has its own JSON file in data/bids/.
    """

    @staticmethod
    def _path(proc_id: str) -> str:
        return os.path.join(BIDS_DIR, f"{proc_id}.json")

    @classmethod
    def _load(cls, proc_id: str) -> dict:
        path = cls._path(proc_id)
        if not os.path.exists(path):
            return {"proc_id": proc_id, "sealed_bids": {}}
        return _read_json(path)

    @classmethod
    def _save(cls, proc_id: str, data: dict):
        _write_json(cls._path(proc_id), data)

    @classmethod
    def store_bid(cls, proc_id: str, envelope: dict) -> bool:
        data = cls._load(proc_id)
        env_id = envelope["envelope_id"]
        if env_id in data["sealed_bids"]:
            return False
        data["sealed_bids"][env_id] = envelope
        cls._save(proc_id, data)
        return True

    @classmethod
    def get_all_bids(cls, proc_id: str) -> list[dict]:
        return list(cls._load(proc_id)["sealed_bids"].values())

    @classmethod
    def bidder_has_submitted(cls, proc_id: str, bidder_username: str) -> bool:
        bids = cls.get_all_bids(proc_id)
        return any(b["bidder_username"] == bidder_username for b in bids)

    @classmethod
    def get_bid_count(cls, proc_id: str) -> int:
        return len(cls.get_all_bids(proc_id))


# ─────────────────────────── Audit Ledger ─────────────────────────────────────

class LedgerStore:
    """
    Append-only hash-chained audit ledger.

    Entry structure:
      entry_hash  = SHA3-256(canonical_json)
      chain_hash  = SHA3-256(prev_chain_hash || entry_hash)
      hmac_sig    = HMAC-SHA256(entry_hash || chain_hash, ledger_key)
      timestamp   = RFC3161-style TSA token

    Chain guarantees: tampering with any entry breaks all subsequent hashes.
    HMAC guarantees: server-side database tampering is detectable.
    """

    GENESIS_HASH = "0" * 64

    @staticmethod
    def _load() -> dict:
        return _read_json(LEDGER_FILE)

    @staticmethod
    def _save(data: dict):
        _write_json(LEDGER_FILE, data)

    @classmethod
    def _prev_chain_hash(cls) -> str:
        data    = cls._load()
        entries = data.get("entries", [])
        return entries[-1]["chain_hash"] if entries else cls.GENESIS_HASH

    @classmethod
    def append(cls, event_type: str, actor: str,
               proc_id: str, payload: dict) -> dict:
        """
        Append a new entry to the ledger.
        Returns the complete entry record.
        """
        data    = cls._load()
        entries = data.get("entries", [])
        prev    = entries[-1]["chain_hash"] if entries else cls.GENESIS_HASH
        seq     = len(entries) + 1

        ts = datetime.now(timezone.utc).isoformat()

        canonical = json.dumps({
            "seq":        seq,
            "event_type": event_type,
            "actor":      actor,
            "proc_id":    proc_id,
            "timestamp":  ts,
            "payload":    payload,
        }, sort_keys=True, separators=(',', ':'))

        entry_hash  = sha3_256_hex(canonical)
        chain_hash  = sha3_256_hex(prev + entry_hash)
        hmac_sig    = hmac_sha256_hex(
            get_ledger_hmac_key(), entry_hash + chain_hash
        )
        ts_token    = TrustedTimestamp.issue(entry_hash)

        entry = {
            "seq":         seq,
            "event_type":  event_type,
            "actor":       actor,
            "proc_id":     proc_id,
            "timestamp":   ts,
            "payload":     payload,
            "entry_hash":  entry_hash,
            "chain_hash":  chain_hash,
            "hmac_sig":    hmac_sig,
            "ts_token":    ts_token,
        }
        entries.append(entry)
        data["entries"] = entries
        cls._save(data)
        return entry

    @classmethod
    def verify_chain(cls) -> tuple[bool, list[str]]:
        """
        Verify full chain integrity.
        Returns (is_valid, list_of_errors).
        """
        data    = cls._load()
        entries = data.get("entries", [])
        errors  = []
        prev    = cls.GENESIS_HASH

        for e in entries:
            # Recompute chain hash
            expected_chain = sha3_256_hex(prev + e["entry_hash"])
            if not hmac.compare_digest(e["chain_hash"], expected_chain):
                errors.append(f"Chain broken at seq {e['seq']}: hash mismatch")

            # Verify HMAC
            expected_hmac = hmac_sha256_hex(
                get_ledger_hmac_key(), e["entry_hash"] + e["chain_hash"]
            )
            if not hmac.compare_digest(e["hmac_sig"], expected_hmac):
                errors.append(f"HMAC invalid at seq {e['seq']}: server tampering detected")

            # Verify timestamp token
            if not TrustedTimestamp.verify(e["ts_token"], e["entry_hash"]):
                errors.append(f"Timestamp invalid at seq {e['seq']}")

            prev = e["chain_hash"]

        return (len(errors) == 0), errors

    @classmethod
    def get_all(cls) -> list[dict]:
        return cls._load().get("entries", [])

    @classmethod
    def get_by_proc(cls, proc_id: str) -> list[dict]:
        return [e for e in cls.get_all() if e.get("proc_id") == proc_id]

    @classmethod
    def get_count(cls) -> int:
        return len(cls.get_all())


# ─────────────────────────── Session Store ────────────────────────────────────

class SessionStore:
    """Simple file-based session for CLI login state."""

    @staticmethod
    def login(username: str, role: str):
        with open(SESSION_FILE, "w") as f:
            json.dump({"username": username, "role": role}, f)

    @staticmethod
    def logout():
        if os.path.exists(SESSION_FILE):
            os.remove(SESSION_FILE)

    @staticmethod
    def current() -> dict | None:
        if not os.path.exists(SESSION_FILE):
            return None
        with open(SESSION_FILE, "r") as f:
            return json.load(f)

    @staticmethod
    def require_login() -> dict:
        session = SessionStore.current()
        if not session:
            raise PermissionError("Not logged in. Use: python main.py login")
        return session

    @staticmethod
    def require_role(role: str) -> dict:
        session = SessionStore.require_login()
        if session["role"] != role:
            raise PermissionError(
                f"Access denied. This action requires role: {role.upper()}"
            )
        return session
