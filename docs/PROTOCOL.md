# DisputeVault Protocol Specification -> v1 (Wave 1)

Status: **Draft for Wave 1 implementation**
Toolchain basis: Compact compiler **0.31.1** (language **0.23.0**, runtime **0.16.0**, ledger **8.0.2**), Midnight ledger-v8 networks.

This document defines the exact on-chain and off-chain data formats used by
DisputeVault. It is precise enough that an independent developer can reproduce
every commitment calculation byte-for-byte in any language.

---

## 1. Overview

DisputeVault separates **private evidence** from **publicly verifiable
commitments**:

```
Claimant browser                      Midnight ledger
----------------                      ---------------
canonical evidence manifest  ──hash──▶ evidence commitment  (public)
    │ (private)                          encrypted envelope   (public)
    └─ encrypt w/ platform pk ─────────▶ dispute status       (public)
                                         verdict commitment   (public)
```

- The **evidence manifest** (canonical JSON, ≤ 256-byte wire) never touches the
  ledger in plaintext. It is a *private witness* to the `submit_dispute`
  circuit; only its Keccak-256 commitment is stored on-chain.
- The **encrypted envelope** (the manifest encrypted to the platform's public
  encryption key) is stored publicly so the authorized adjudication worker can
  later decrypt and adjudicate.
- The **verdict** is committed on-chain; the verdict payload itself lives
  off-chain and can be re-hashed by anyone to verify the commitment.

All commitments are **Keccak-256 over a fixed-size wire encoding** of the
canonical JSON. The wire encoding embeds a magic tag and the JSON length, so
commitments are unambiguous and domain-separated.

---

## 2. Canonical JSON rules

Every payload is serialized with these rules. The frontend (TypeScript), the
Go worker, and any verifier MUST produce byte-identical output:

1. **Fixed field order** - fields appear exactly in the order defined by the
   schema below (insertion order, *not* alphabetical).
2. **UTF-8 encoding**, no byte-order mark.
3. **No whitespace** - no spaces, newlines, or indentation.
4. **Integers** - plain decimal ASCII, no leading `+`, no leading zeros, no
   exponents, no fractional part.
5. **Strings** - minimal JSON escaping: `\"`, `\\`, and control characters as
   `\u00XX`. Non-ASCII characters are emitted raw as UTF-8 (not `\uXXXX`).
6. **Hash fields** - 32 lowercase hex characters (16-byte truncated Keccak-256
   of the referenced data; see §5.2).
7. **No extra fields** - unknown fields are rejected, not ignored.
8. **Size limit** - the canonical JSON MUST fit within the wire budget
   (§3). Oversized payloads are **rejected with an error**; nothing is ever
   truncated.

---

## 3. Wire format

Circuits require fixed-size inputs, so each payload is embedded in a
fixed-size wire:

```
offset  size  field
0       4     magic          ASCII "DV1E" (evidence) or "DV1V" (verdict)
4       2     json_len       uint16 big-endian, length of the canonical JSON
6       n     json           canonical JSON bytes (n == json_len)
6+n     ...   padding        0x00 bytes up to the fixed wire size
```

| Payload  | Wire size | Max canonical JSON |
| -------- | --------- | ------------------ |
| Evidence | 256 bytes | 250 bytes          |
| Verdict  | 192 bytes | 186 bytes          |

Rules:

- The JSON length must be consistent: `json_len == number of JSON bytes`, and
  `6 + json_len <= wire size`.
- Padding bytes MUST be zero. Any non-zero padding invalidates the wire.
- The magic byte tag doubles as **domain separation**: an evidence commitment
  can never equal a verdict commitment over different payload types.

**Implementation note:** TypeScript uses `TextEncoder` (UTF-8). Go uses plain
string/byte handling (Go strings are UTF-8). Both sides MUST count **bytes**,
not Unicode code points, when checking `json_len`.

---

## 4. EvidenceV1 schema

Canonical field order:

| Field               | Type            | Constraint                             |
| ------------------- | --------------- | -------------------------------------- |
| `v`                 | integer         | `1`                                    |
| `bounty_id`         | integer         | `0 .. 4294967295` (Uint<32>)           |
| `claimant_id_hash`  | hex string      | 32 lowercase hex chars (16 bytes)      |
| `type`              | integer         | `0..3` (see dispute types below)       |
| `evidence_ref_hash` | hex string      | 32 lowercase hex chars (16 bytes)      |
| `summary`           | string          | ≤ 64 characters; must fit size budget  |

Dispute types:

| Value | Meaning                |
| ----- | ---------------------- |
| `0`   | rejected-valid-work    |
| `1`   | payment-not-received   |
| `2`   | scope-dispute          |
| `3`   | other                  |

Example canonical manifest (218 bytes):

```json
{"v":1,"bounty_id":42,"claimant_id_hash":"9f86d081884c7d659a2feaa0c55ad015","type":1,"evidence_ref_hash":"60303ae22b998861bce3b28f33eec1be","summary":"Payment was not received for completed bounty."}
```

The **actual evidence bundle** (PR links, screenshots, payment records, chat
exports, documents) stays off-chain. `evidence_ref_hash` is the commitment to
that bundle. The manifest is the only thing committed on-chain.

---

## 5. Commitments and hashing

### 5.1 Hash primitive

`keccak256` - standard Keccak-256 (legacy Keccak padding, **not** SHA3-256),
producing a 32-byte digest. This primitive is available in all three stacks:

- **Compact circuit** - `keccak256(value: Bytes<N>): Bytes<32>` from
  `CompactStandardLibrary` (in-circuit, enforced by the ZK proof).
- **TypeScript** - `@midnight-ntwrk/compact-runtime` `keccak256(rtType, value)`
  or `@noble/hashes` `keccak256` (verified byte-identical for `Bytes<N>`
  inputs; see `sdk/test` cross-checks).
- **Go** - `golang.org/x/crypto/sha3` `NewLegacyKeccak256`.

### 5.2 Truncated references

`claimant_id_hash` and `evidence_ref_hash` are **16-byte truncated
Keccak-256** digests (first 16 bytes of the full digest), encoded as 32
lowercase hex characters. Truncation keeps the manifest inside the 250-byte
budget. Full digests remain possible in Wave 2 by growing the wire.

### 5.3 Commitment computation

```
evidence_commitment = Keccak256(evidence_wire)      # exactly the 256 wire bytes
verdict_commitment  = Keccak256(verdict_wire)       # exactly the 192 wire bytes
```

Both are computed **inside the circuit** over the private payload bytes and
stored on-chain, so the proof enforces commitment ↔ payload binding.

---

## 6. Encryption (evidence envelope)

Wave 1 uses WebCrypto-compatible primitives available in every browser, in
Node.js, and in the Go standard library - no third-party crypto dependency:

```
Platform keypair        P-256 (secp256r1)
  private key           held ONLY by the Go adjudication worker
  public key            raw uncompressed point, 65 bytes (0x04 || X || Y)
                        stored on-chain by register_platform

ECDH                    shared secret = x-coordinate of
                        ECDH(platform_priv, claimant_ephemeral_pub)
                        (32 bytes, used directly as the AES-256 key)

AEAD                    AES-256-GCM, 12-byte random nonce, 16-byte tag
plaintext               the full 256-byte evidence wire
```

Envelope layout (284 bytes, stored publicly in the ledger):

```
offset  size  field
0       12    nonce
12      272   ciphertext = GCM(wire256) + 16-byte auth tag
```

Rules:

- The ephemeral keypair is generated fresh per dispute by the claimant.
- The claimant never sees the platform private key; the platform never sees
  the claimant's static key (there isn't one - only ephemeral keys).
- Plaintext evidence is never logged, never sent to the gateway, and never
  committed to git.
- GCM additionally authenticates the nonce and ciphertext as a unit; any
  tampering makes decryption fail.

> **Wave 1 limitation (documented, intentional):** the on-chain proof binds
> `evidence_commitment` to the plaintext *witness* and stores the envelope,
> but cannot itself verify that the envelope decrypts to that plaintext
> (P-256/AES are not available in-circuit). The adjudication worker MUST
> decrypt the envelope, re-canonicalize, re-hash, and compare against the
> on-chain commitment before adjudicating; a mismatch is escalated to
> `needs_human_review` and never adjudicated. See SECURITY.md §6.

---

## 7. VerdictV1 schema

Canonical field order:

| Field            | Type       | Constraint                                  |
| ---------------- | ---------- | ------------------------------------------- |
| `v`              | integer    | `1`                                          |
| `dispute_id`     | integer    | `0 .. 2^64-1`; MUST equal the outer dispute |
| `decision`       | enum       | `claimant_wins | platform_wins | partial | needs_human_review` |
| `confidence`     | integer    | `0..100`                                     |
| `reason_code`    | string     | `A-Z0-9_`, ≤ 32 chars                        |
| `policy_version` | string     | ≤ 32 chars, pattern `[a-z0-9-]+`             |

Example canonical verdict (≈ 142 bytes):

```json
{"v":1,"dispute_id":42,"decision":"claimant_wins","confidence":87,"reason_code":"PAYMENT_NOT_VERIFIED","policy_version":"bounty-dispute-v1"}
```

**Binding rule (mandatory):** `verdict.dispute_id` MUST equal the dispute id
supplied to `post_verdict`. The circuit cannot parse JSON, so this rule is
enforced by every off-chain component that publishes or verifies (worker,
gateway, verification UI) and by the contract tests. A mismatched payload is
rejected before it can be committed.

The long-form human-readable LLM explanation is **not** part of the
commitment. It stays off-chain with the verdict payload.

---

## 8. Dispute lifecycle

```
        register_platform (once, admin)
                    │
                    ▼
  ┌─────────────────────────────────────────────┐
  │ claimant builds canonical manifest          │
  │ wire = DV1E header + JSON + pad             │
  │ encrypt wire → envelope (platform pk)       │
  │ submit_dispute(manifest_witness, envelope)  │
  └─────────────────────────────────────────────┘
                    │  circuit: id = ++counter
                    │  ledger[id] = { evidence_commitment, envelope, SUBMITTED }
                    ▼
              SUBMITTED
                    │  worker: fetch → decrypt → re-hash (== commitment?)
                    │          → adjudicate → canonical verdict → hash
                    │  post_verdict(dispute_id, verdict_witness)
                    ▼
  ledger[id].verdict_commitment = Keccak256(verdict_wire)
  ledger[id].status = VERDICT_POSTED
```

- Dispute ids start at **1** and are allocated by the ledger `Counter`.
- A dispute is created at most once (fresh counter id — evidence can never be
  overwritten).
- A verdict is posted at most once (`status` guard in the circuit).

---

## 9. Authorization

The contract uses the **hash-based authentication pattern** from the official
Midnight security documentation (`docs/compact/smart-contract-security`):

```
admin secret (witness, private)
        │  adminPk(sk) = persistentHash([pad(32,"disputevault:admin:pk"), sk])
        ▼
admin_authority (Bytes<32>, on-chain, bound at deployment)
```

- `admin_authority` is bound **in the constructor** from a private deployment
  argument; it cannot be changed (no circuit writes it after deployment).
- `register_platform` and `post_verdict` obtain the admin secret through the
  `adminSecret()` **witness**, derive `adminPk(sk)` **inside the circuit**,
  and `assert(adminPk(sk) == admin_authority)`.
- `ownPublicKey()` is **never** used for authorization (explicitly warned
  against in the current Midnight docs — it is a witness function a malicious
  frontend can fake).
- The **platform encryption keypair** is a separate key with a separate
  purpose (evidence decryption), stored on-chain by `register_platform`.
  It is *not* the admin key.

---

## 10. Verification procedures

### Evidence (public verifier)

```
input: dispute_id, canonical evidence manifest
1. canonicalize manifest  (§2, §4)
2. wire  = DV1E header + json + zero pad to 256      (§3)
3. hash  = Keccak256(wire)                            (§5.3)
4. fetch ledger[dispute_id].evidence_commitment from the gateway/indexer
5. result = (hash == stored commitment)
```

### Verdict (public verifier)

```
input: dispute_id, canonical verdict payload
1. canonicalize verdict    (§2, §7)
2. assert payload.dispute_id == dispute_id            (§7 binding rule)
3. wire  = DV1V header + json + zero pad to 192
4. hash  = Keccak256(wire)
5. fetch ledger[dispute_id].verdict_commitment
6. result = (hash == stored commitment)
```

Failure states are explicit and user-visible: `✗ Commitment does not match`.

---

## 11. Limits summary

| Limit                        | Value      |
| ---------------------------- | ---------- |
| Evidence wire size           | 256 bytes  |
| Evidence canonical JSON max  | 250 bytes  |
| Evidence `summary` max       | 64 chars   |
| Verdict wire size            | 192 bytes  |
| Verdict canonical JSON max   | 186 bytes  |
| Verdict `reason_code` max    | 32 chars   |
| Verdict `policy_version` max | 32 chars   |
| Truncated reference hashes   | 16 bytes   |
| Envelope size                | 284 bytes  |
| `bounty_id`                  | Uint<32>   |
| `dispute_id`                 | Uint<64>   |

Any violation is a hard error. There is no silent truncation anywhere in the
system.
