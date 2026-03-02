"""
CSePS Cryptographic Engine
===========================
All cryptographic primitives:
  - ECC SECP384R1 key generation & serialisation
  - ECDH + HKDF + AES-256-GCM hybrid encryption
  - ECDSA + SHA3-256 digital signatures
  - SHA3-256 commitment scheme
  - HMAC-SHA256 ledger integrity
  - RFC 3161-style trusted timestamps
  - Shamir Secret Sharing (XOR simulation)
"""

import hmac
import base64
import hashlib
import secrets
import json
from datetime import datetime, timezone
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP384R1, generate_private_key, ECDH,
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from config import AES_KEY_BYTES, GCM_NONCE_BYTES, HKDF_INFO

# ── Persistent HMAC key for ledger integrity ─────────────────────────────────
# Written once on first run, reloaded on every subsequent run.
# In production: store in HSM / key vault.

import os as _os

def _load_or_create_hmac_key() -> bytes:
    from config import DATA_DIR
    key_path = _os.path.join(DATA_DIR, ".ledger_key")
    _os.makedirs(DATA_DIR, exist_ok=True)
    if _os.path.exists(key_path):
        with open(key_path, "rb") as f:
            return f.read()
    key = secrets.token_bytes(32)
    with open(key_path, "wb") as f:
        f.write(key)
    _os.chmod(key_path, 0o600)
    return key


def get_ledger_hmac_key() -> bytes:
    return _load_or_create_hmac_key()


# ─────────────────────────── Key Management ───────────────────────────────────

class KeyManager:
    """
    ECC SECP384R1 key generation and PEM serialisation.
    P-384 provides ~192-bit security — NIST Suite B for SECRET-level data.
    """

    CURVE = SECP384R1()

    @classmethod
    def generate_keypair(cls) -> tuple:
        priv = generate_private_key(cls.CURVE, default_backend())
        return priv, priv.public_key()

    @staticmethod
    def private_key_to_pem(key, password: bytes = None) -> str:
        enc = (serialization.BestAvailableEncryption(password)
               if password else serialization.NoEncryption())
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, enc
        ).decode()

    @staticmethod
    def public_key_to_pem(key) -> str:
        return key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    @staticmethod
    def load_private_key(pem: str, password: bytes = None):
        return serialization.load_pem_private_key(
            pem.encode(), password, default_backend()
        )

    @staticmethod
    def load_public_key(pem: str):
        return serialization.load_pem_public_key(pem.encode(), default_backend())

    @staticmethod
    def fingerprint(public_key_pem: str) -> str:
        """SHA3-256 fingerprint of a public key (first 16 hex chars)."""
        raw = public_key_pem.encode()
        return hashlib.sha3_256(raw).hexdigest()[:16].upper()


# ─────────────────────────── Hybrid Encryption ────────────────────────────────

class HybridEncryption:
    """
    ECDH ephemeral + HKDF + AES-256-GCM.

    Encryption (bidder side):
      1. Generate one-time ephemeral ECC key pair
      2. ECDH(eph_priv, authority_pub) → shared_secret
      3. HKDF-SHA3-256(shared_secret) → 256-bit AES key
      4. AES-256-GCM encrypt bid payload

    Decryption (authority side):
      1. ECDH(authority_priv, eph_pub) → same shared_secret
      2. Same HKDF → same AES key
      3. AES-256-GCM decrypt + verify auth tag

    Security: Perfect forward secrecy via unique ephemeral key per bid.
    """

    @staticmethod
    def encrypt(plaintext: bytes, recipient_pub_pem: str) -> dict:
        """Encrypt plaintext. Returns dict with all fields needed for decryption."""
        recipient_pub = KeyManager.load_public_key(recipient_pub_pem)
        eph_priv, eph_pub = KeyManager.generate_keypair()

        shared_secret = eph_priv.exchange(ECDH(), recipient_pub)
        aes_key = HKDF(
            algorithm=hashes.SHA3_256(),
            length=AES_KEY_BYTES,
            salt=None,
            info=HKDF_INFO,
            backend=default_backend()
        ).derive(shared_secret)

        nonce      = secrets.token_bytes(GCM_NONCE_BYTES)
        ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)

        return {
            "ephemeral_pub_pem": KeyManager.public_key_to_pem(eph_pub),
            "ciphertext_b64":    base64.b64encode(ciphertext).decode(),
            "nonce_b64":         base64.b64encode(nonce).decode(),
        }

    @staticmethod
    def decrypt(enc_data: dict, recipient_priv_pem: str) -> bytes:
        """
        Decrypt using authority private key.
        Raises InvalidTag if ciphertext was tampered.
        """
        recipient_priv = KeyManager.load_private_key(recipient_priv_pem)
        eph_pub        = KeyManager.load_public_key(enc_data["ephemeral_pub_pem"])
        ciphertext     = base64.b64decode(enc_data["ciphertext_b64"])
        nonce          = base64.b64decode(enc_data["nonce_b64"])

        shared_secret = recipient_priv.exchange(ECDH(), eph_pub)
        aes_key = HKDF(
            algorithm=hashes.SHA3_256(),
            length=AES_KEY_BYTES,
            salt=None,
            info=HKDF_INFO,
            backend=default_backend()
        ).derive(shared_secret)

        return AESGCM(aes_key).decrypt(nonce, ciphertext, None)


# ─────────────────────────── Digital Signature ────────────────────────────────

class DigitalSignature:
    """
    ECDSA over SECP384R1 with SHA3-256.
    Provides authenticity and non-repudiation.
    """

    @staticmethod
    def sign(data: bytes, private_key_pem: str) -> str:
        """Sign data, return base64-DER signature string."""
        priv = KeyManager.load_private_key(private_key_pem)
        sig  = priv.sign(data, ec.ECDSA(hashes.SHA3_256()))
        return base64.b64encode(sig).decode()

    @staticmethod
    def verify(data: bytes, signature_b64: str, public_key_pem: str) -> bool:
        """Verify signature. Returns True if valid."""
        try:
            pub = KeyManager.load_public_key(public_key_pem)
            pub.verify(base64.b64decode(signature_b64), data, ec.ECDSA(hashes.SHA3_256()))
            return True
        except (InvalidSignature, Exception):
            return False


# ─────────────────────────── Commitment Scheme ────────────────────────────────

class CommitmentScheme:
    """
    SHA3-256 cryptographic commitment (hiding + binding).

    commit = SHA3-256(ciphertext_b64 || "|" || nonce_b64)

    Hiding:  Reveals nothing about bid content.
    Binding: Bidder cannot change ciphertext after committing.
    """

    @staticmethod
    def commit(ciphertext_b64: str, nonce_b64: str) -> str:
        raw = (ciphertext_b64 + "|" + nonce_b64).encode()
        return hashlib.sha3_256(raw).hexdigest()

    @staticmethod
    def verify(commitment: str, ciphertext_b64: str, nonce_b64: str) -> bool:
        expected = CommitmentScheme.commit(ciphertext_b64, nonce_b64)
        return hmac.compare_digest(commitment, expected)


# ─────────────────────────── Trusted Timestamp ────────────────────────────────

class TrustedTimestamp:
    """
    RFC 3161-inspired timestamp token.
    Production: call DigiCert/GlobalSign TSA.
    Prototype:  HMAC-SHA3-256 signed with the ledger key.
    """

    @staticmethod
    def issue(data_hash: str) -> dict:
        ts    = datetime.now(timezone.utc).isoformat()
        body  = f"{ts}|{data_hash}"
        token = hmac.new(
            get_ledger_hmac_key(), body.encode(), hashlib.sha3_256
        ).hexdigest()
        return {"issued_at": ts, "data_hash": data_hash, "tsa_token": token}

    @staticmethod
    def verify(token: dict, data_hash: str) -> bool:
        body     = f"{token['issued_at']}|{data_hash}"
        expected = hmac.new(
            get_ledger_hmac_key(), body.encode(), hashlib.sha3_256
        ).hexdigest()
        return hmac.compare_digest(expected, token["tsa_token"])


# ─────────────────────────── Hash Utilities ───────────────────────────────────

def sha3_256_hex(data: str) -> str:
    return hashlib.sha3_256(data.encode()).hexdigest()


def hmac_sha256_hex(key: bytes, data: str) -> str:
    return hmac.new(key, data.encode(), hashlib.sha256).hexdigest()


# ─────────────────────────── Shamir Secret Sharing ────────────────────────────

class ThresholdKey:
    """
    Threshold key splitting ceremony.
    XOR-based n-of-n split (demonstration).
    Production: use polynomial GF(2^8) Shamir SSS for true t-of-n.
    """

    @staticmethod
    def split(secret: bytes, n: int) -> list[bytes]:
        """Split secret into n shares. All n required to reconstruct."""
        shares = [secrets.token_bytes(len(secret)) for _ in range(n - 1)]
        last   = secret
        for s in shares:
            last = bytes(a ^ b for a, b in zip(last, s))
        shares.append(last)
        return shares

    @staticmethod
    def reconstruct(shares: list[bytes]) -> bytes:
        """Reconstruct secret from all shares."""
        result = shares[0]
        for s in shares[1:]:
            result = bytes(a ^ b for a, b in zip(result, s))
        return result

    @staticmethod
    def shares_to_hex(shares: list[bytes]) -> list[str]:
        return [s.hex() for s in shares]

    @staticmethod
    def shares_from_hex(hex_shares: list[str]) -> list[bytes]:
        return [bytes.fromhex(h) for h in hex_shares]
