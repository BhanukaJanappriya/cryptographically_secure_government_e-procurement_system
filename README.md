---

## Overview Document

---

# CSePS — Complete Technical Overview

## 1. Problem Statement

Traditional government e-procurement suffers from four well-documented attack vectors:

| Problem | Impact |
|---|---|
| **Early bid leakage** | Officials read competing bids, enabling favouritism |
| **Bid tampering** | Bids modified post-submission to disqualify competitors |
| **Repudiation disputes** | "I never submitted that bid" — no cryptographic proof |
| **Opaque processes** | Public cannot verify no bid was opened prematurely |

CSePS solves all four using applied cryptography, without requiring any trusted central authority to "behave honestly."

---

## 2. System Architecture
```
┌──────────────────────────────────────────────────────────────────┐
│                    PROCUREMENT PORTAL (Public)                   │
│  ┌─────────────┐    ┌──────────────────────────────────────────┐ │
│  │  Bidder A   │    │          AUDIT LEDGER (Public)           │ │
│  │  Bidder B   │───▶│  Entry 1: commitment | chain_hash | HMAC │ │
│  │  Bidder C   │    │  Entry 2: commitment | chain_hash | HMAC │ │
│  └─────────────┘    │  Entry N: commitment | chain_hash | HMAC │ │
│                     └──────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │              PROCUREMENT AUTHORITY (Private)                │  │
│  │  ECC P-384 Private Key (split via Shamir across officers)   │  │
│  │  Deadline gate: key only released at T_deadline             │  │
│  └─────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

The key insight: **all encrypted bids are public, but unreadable**. Anyone can verify no bid was tampered with or opened early, even while the content remains secret.

---

## 3. What's Implemented — Module by Module

### 3.1 Key Management (`KeyManager`)

**Curve chosen:** SECP384R1 (NIST P-384)

P-384 provides ~192-bit security — the US NSA's Suite B requirement for protecting SECRET-level government data. Each entity (bidder + authority) generates an independent ECC key pair. Bidder private keys never leave the bidder's machine; only public keys are registered with the authority.

**Why ECC over RSA?** ECC offers equivalent security with dramatically shorter keys (384 bits vs 3072-bit RSA), making signatures and key exchange faster and ledger entries smaller.

### 3.2 Hybrid Encryption (`HybridEncryption`)

The bid payload encryption uses a three-layer hybrid scheme:
```
BidPayload (JSON)
    │
    ▼
[Step 1] Bidder generates ephemeral ECC key pair (eph_priv, eph_pub)
    │
    ▼
[Step 2] ECDH(eph_priv, authority_pub) → shared_secret (48 bytes)
    │
    ▼
[Step 3] HKDF(SHA3-256, shared_secret, info="CSePS-bid-v1") → aes_key (32 bytes)
    │
    ▼
[Step 4] AES-256-GCM(aes_key, nonce=96-bit-random).encrypt(payload)
    │
    ▼  eph_pub_pem + ciphertext_b64 + nonce_b64  → stored in SealedBid
```

The ephemeral key ensures **perfect forward secrecy**: even if the authority's private key is later compromised, past bids from different sessions remain secure because each used a unique ephemeral key.

Only the holder of `authority_priv` can compute the same ECDH shared secret and thus reconstruct the AES key. The AES-GCM authentication tag (embedded in the ciphertext) ensures any tampering causes decryption to fail with `InvalidTag`.

### 3.3 Digital Signatures (`DigitalSignature`)

Every bidder signs their **commitment hash** (not the raw bid) with ECDSA/SHA3-256:
```
signature = ECDSA_sign(SHA3-256, commitment_hash, bidder_private_key)
```

This achieves two properties simultaneously:

- **Authenticity:** The signature can only be produced by the legitimate key holder.
- **Non-repudiation:** The signature is mathematically bound to both the bidder's key and the specific commitment. If a bidder later claims "I didn't submit that bid," the verifiable signature proves otherwise, forever.

The authority verifies this signature at submission time, **before** accepting the bid onto the ledger.

### 3.4 Commitment Scheme (`CommitmentScheme`)
```
commitment = SHA3-256(ciphertext_b64 || "|" || nonce_b64)
```

This is a **hiding + binding** commitment:
- **Hiding:** The commitment reveals nothing about the bid content (SHA3 is a one-way function).
- **Binding:** The bidder cannot change their ciphertext after committing — any modification produces a completely different hash (SHA3's avalanche effect).

The commitment is stored on the public ledger immediately upon submission. Before opening any bid, the authority re-computes and compares the commitment. This provides a **before/after integrity proof**: if the ciphertext in the database differs from what was committed, the tampering is caught.

### 3.5 Trusted Timestamps (`TrustedTimestamp`)

Each commitment is timestamped using an HMAC-signed token:
```
token_body = ISO8601_timestamp || "|" || commitment_hash
tsa_token  = HMAC-SHA3-256(LEDGER_HMAC_KEY, token_body)
```

This proves **when** a commitment was registered. In production, this would call an RFC 3161-compliant external TSA (e.g., DigiCert, GlobalSign), whose root certificate is independently trusted. The timestamp proves bids were registered before the deadline, preventing back-dated submission attacks.

### 3.6 Append-Only Hash-Chained Audit Ledger (`AuditLedger`)

The ledger is a lightweight blockchain. Each entry contains:
```
entry_hash  = SHA3-256(canonical_json)
chain_hash  = SHA3-256(previous_chain_hash || entry_hash)
hmac_sig    = HMAC-SHA256(entry_hash || chain_hash)
```

This chain structure means:
- **Append-only:** Inserting or deleting any entry breaks all subsequent chain hashes.
- **Publicly verifiable:** Any third party can recompute all chain hashes and verify integrity — no HMAC key needed for chain verification.
- **Server-tamper resistant:** The HMAC protects against a malicious database administrator directly editing rows.

The genesis hash is `"0" * 64`, making the chain independently reproducible from scratch.

### 3.7 Shamir Secret Sharing (`ThresholdKeySimulator`)

The procurement authority's decryption private key is split into `n` shares held by `n` different officials. No single official can open bids alone. Only `t` cooperating officials can reconstruct the key.
```
Architecture:
  Key → split → [Share₁ to Officer A] [Share₂ to Officer B] [Share₃ to Officer C]
  
  Opening ceremony: Officers A + B + C meet, contribute shares → reconstruct key
```

This eliminates the single-point-of-trust problem. Even if one official is corrupt or coerced, they cannot open bids prematurely. In production, a GF(2⁸) polynomial Shamir implementation (e.g., `python-secretsharing`) supports true `(t < n)` thresholds.

### 3.8 Public Verifier (`PublicVerifier`)

This module requires **zero private keys**. Any auditor — a journalist, opposition party, or citizen — can:

1. Download the public ledger JSON
2. Re-compute all chain hashes from scratch
3. Verify every bid's commitment matches the ledger entry
4. Verify every ECDSA signature using the bidder's published public key
5. Confirm non-repudiation for any specific bidder

This is the core of **verifiable fairness**: the system is transparent without being readable.

---

## 4. Threat Model & Mitigations

| Threat | Mitigation |
|---|---|
| Corrupt official reads bids early | AES-256-GCM: ciphertext unreadable without ECDH private key |
| Corrupt official modifies a bid | Commitment hash + ECDSA signature detect any modification |
| Bidder denies submitting a bid | ECDSA signature + ledger timestamp proves submission |
| Back-dated submission attack | RFC 3161 timestamp token proves registration time |
| Database administrator deletes entries | Hash chain: deletion breaks all subsequent hashes |
| Single corrupt key holder opens early | Shamir threshold: requires t-of-n cooperation |
| Bidder submits under another's identity | ECDSA verification with registered public keys rejects forgery |
| Replay attack (resubmit old bid) | `nonce_salt` in payload + unique envelope IDs prevent replays |
| AES-GCM nonce reuse | `secrets.token_bytes(12)` generates fresh 96-bit nonce per bid |
| Future key compromise exposes past bids | Ephemeral ECDH keys ensure perfect forward secrecy |

---

## 5. Security Parameters

| Parameter | Value | Security Level |
|---|---|---|
| ECC Curve | SECP384R1 (P-384) | ~192-bit |
| Signature algorithm | ECDSA + SHA3-256 | NIST Suite B |
| Hash function | SHA3-256 (Keccak) | 256-bit preimage resistance |
| AES key length | 256-bit | 256-bit security |
| GCM nonce | 96-bit random | Negligible collision probability |
| HKDF info string | "CSePS-bid-v1" | Domain separation |
| HMAC algorithm | HMAC-SHA256 | 256-bit MAC security |

---

## 6. Workflow Phases
```
Phase 1:  Authority generates ECC key pair, publishes public key
Phase 2:  Bidders register, generate their own ECC key pairs
Phase 3:  Bidders submit sealed encrypted bid envelopes
Phase 4:  Public auditors verify ledger chain (pre-deadline)
Phase 5:  At deadline: threshold key ceremony reconstructs authority key
Phase 6:  Authority decrypts all bids simultaneously (fairness)
Phase 7:  Results published; public re-verifies commitments
Phase 8:  Audit artifacts saved for long-term accountability
```

---

## 7. Production Deployment Notes

To graduate this prototype to production, the following enhancements would be needed:

- **HSM integration** — Authority private key stored in a Hardware Security Module (e.g., AWS CloudHSM, Thales Luna), never exposed in software memory.
- **External TSA** — Replace HMAC timestamps with RFC 3161 calls to a certified TSA (DigiCert, GlobalSign).
- **True Shamir SSS** — Replace XOR splitting with polynomial GF(2⁸) Shamir using a vetted library.
- **Zero-Knowledge Proofs** — Prove bid validity (e.g., price within bounds) without revealing content, using zk-SNARKs.
- **Blockchain anchoring** — Periodically anchor the ledger root hash to a public blockchain (Ethereum, Bitcoin) for independent immutability.
- **PKI / CA infrastructure** — Bidder key registration via a government PKI with identity-verified certificates.
- **Secure multi-party computation** — For threshold decryption without ever reconstructing the full key in a single location.

---

## 8. File Structure
```
cseps/
├── cseps.py              ← Complete implementation (single file)
├── requirements.txt      ← cryptography>=41.0.0
└── cseps_audit_ledger.json  ← Generated on each run
```

`requirements.txt`:
```
cryptography>=41.0.0
