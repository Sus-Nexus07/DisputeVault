# DisputeVault -> Security

Wave 1 threat model, trust assumptions, and known limitations.

---

## 1. Security goals

1. Raw evidence never appears in plaintext on Midnight or in any public log.
2. No one can replace the platform encryption key after registration.
3. No one except the authorized adjudicator can publish a verdict.
4. Verdicts and evidence cannot be overwritten, duplicated, or swapped between
   disputes.
5. Anyone can independently verify that a published commitment corresponds to
   a claimed payload.

---

## 2. Threat model

| Adversary | Capabilities | Mitigations |
| --- | --- | --- |
| Public observer | Reads all on-chain data | Sees only commitments, envelopes (ciphertext), ids, status |
| Malicious claimant | Submits crafted disputes | Circuit enforces canonical-size wire + commitment binding; ids cannot collide |
| Malicious third party | Calls any circuit | Verdict/registration paths require admin secret proof (§4) |
| Compromised frontend | Feeds fake witness values | Authorization never relies on `ownPublicKey()`; admin secret proven in-circuit |
| Malicious worker | Adjudicates dishonestly | Verdict commitment binds the payload; human review flag available; documented trust assumption (§7) |
| Colluding gateway | Sees ciphertext + metadata only | Cannot decrypt (no platform private key), cannot forge verdicts (no admin secret) |

---

## 3. Platform-key hijacking (Attack 1)

**Attack:** after legitimate `register_platform`, an attacker calls
`register_platform` again with their own encryption key, so future claimants
encrypt evidence to the attacker.

**Defense:**
- The circuit asserts the platform key is still the default (zero) value
  before writing; a second registration **fails the assert** and the
  transaction is rejected.
- Registration additionally requires the admin secret proof, so even the
  *first* registration can only be performed by the deployer authority.

**Test:** `contract/src/test` - "does not let a second registration replace
the platform key" and "does not let an unauthorized caller register".

---

## 4. Authorization design

The current Midnight security documentation explicitly warns:

> Never use `ownPublicKey()` for verification of the caller of a particular
> Compact circuit. `ownPublicKey()` is technically a witness function and each
> user frontend is capable of producing a malicious return from an
> `ownPublicKey()` call.

DisputeVault therefore uses the documented **hash-based authentication**
pattern:

```
adminSecret() witness  ──▶ adminPk(sk) = persistentHash([pad(32,"disputevault:admin:pk"), sk])
                              │
                              ▼
                 assert(adminPk(sk) == admin_authority)   // in-circuit
```

- `admin_authority` is bound **in the constructor** from the deployer's
  secret; no circuit can change it afterwards.
- The derivation happens **inside the circuit**, so a proof of
  `post_verdict` / `register_platform` implies knowledge of the admin secret.
- The secret never leaves the worker/admin frontend; it arrives as a witness
  result at proof-generation time.

Residual risk: whoever holds the admin secret holds adjudication authority.
It is an operator key and must be protected like production infrastructure
(§9).

---

## 5. Verdict integrity (Attacks 2-4, 6)

| Attack | Mechanism | Defense |
| --- | --- | --- |
| Fake verdict (2) | Unauthorized account posts a verdict | In-circuit admin proof; no admin secret → no valid proof → tx rejected |
| Nonexistent dispute (3) | `post_verdict(dispute_id=999999)` | `disputes.member(id)` assert |
| Duplicate verdict (4) | Two verdicts for one dispute | `status == SUBMITTED` assert; status flips to `VERDICT_POSTED` in the same circuit |
| Verdict/dispute mismatch (6) | Outer id 42, payload says 99 | Off-chain binding rule enforced by worker/gateway/verifier (circuit cannot parse JSON); documented in PROTOCOL §7 |

**Defense in depth for (6):** the worker derives `dispute_id` for the verdict
payload from the dispute record it fetched - the caller-supplied id is never
trusted - and the gateway re-checks the binding before constructing the
transaction. Verification UI also checks it, so a mismatched commitment can
never be presented as valid.

---

## 6. Evidence integrity and the envelope gap (Attacks 5, 7)

**Evidence overwrite (5):** dispute ids come from a monotonic ledger
`Counter`; `submit_dispute` always writes a **fresh** key. There is no code
path that writes to an existing id, so overwrite is structurally impossible.

**Oversized evidence (7):** the wire format is fixed-size (256 bytes) with an
explicit length field and zero-padding; the circuit input type is
`Bytes<256>`. A payload that does not fit is rejected client-side and
worker-side with an explicit error - never truncated.

**The envelope gap (honest disclosure):** the circuit proves the *witness
plaintext* hashes to the stored commitment, but cannot verify that the
*envelope* encrypts that same plaintext (P-256/AES-GCM are not in-circuit
provable in Wave 1). A malicious claimant could therefore submit a valid
commitment over plaintext A while the envelope contains ciphertext of B.

Mitigations:
- The worker decrypts, re-canonicalizes, re-hashes, and compares against the
  on-chain commitment **before adjudicating**. Mismatch -> dispute is flagged
  `needs_human_review`, never adjudicated.
- The gap is closed properly in Wave 2 by moving the wire hash into the
  AEAD's associated data (binding envelope <-> commitment cryptographically) or
  by proving encryption correctness in-circuit.

---

## 7. Plaintext leakage

- Plaintext evidence exists only: in the claimant's browser tab, and in the
  worker's memory after decryption.
- The worker never logs payloads; logs carry dispute ids and status only.
- The gateway never receives plaintext evidence - only commitments and
  envelopes.
- Git hygiene: `.env` ignored; test fixtures use synthetic data only.

---

## 8. Key management (Wave 1)

| Key | Location | Rotation |
| --- | --- | --- |
| Admin secret | Operator env (`ADMIN_SECRET`) | Not rotatable on-chain in Wave 1 (authority fixed at deployment). Wave 2: authority-rotation circuit with two-step commit/reveal. |
| Platform encryption private key | Worker env (`PLATFORM_ENCRYPTION_PRIVATE_KEY`) | Fixed at registration in Wave 1. Loss = historical evidence unreadable; compromise = historical evidence readable. Wave 2: key rotation with re-encryption protocol. |
| Claimant ephemeral keys | Per-dispute, in-browser | Ephemeral by design |

All keys are loaded from environment variables; none are committed.

---

## 9. AI trust limitations

**What the ZK proof proves:** the published `verdict_commitment` was computed
over the canonical verdict payload by the circuit, and the publisher knew the
admin secret. Integrity and authorization - *not correctness*.

**What it does NOT prove:** that the AI made the *correct* decision. The LLM
is an off-chain advisory component. `confidence` and `needs_human_review`
exist precisely because automated adjudication can be wrong. Do not represent
DisputeVault as "ZK-verified AI justice"; it is *cryptographically committed,
authorized publication of a dispute outcome*.

---

## 10. Wave 1 trust assumptions (summary)

1. The platform operator (holder of admin secret + platform private key) is
   trusted with decrypted evidence and with honest adjudication.
2. The LLM provider is trusted for availability, not correctness.
3. The gateway is trusted for liveness, not confidentiality or integrity of
   adjudication.
4. The Midnight proof system is trusted for circuit correctness.

Every assumption above has a documented Wave 2/3 mitigation path (see
PROPOSAL.md roadmap): two-party encryption, in-circuit envelope binding,
multi-model consensus, decentralized reviewer marketplace.

---

## 11. Future improvements

- Envelope <-> commitment binding via AEAD associated data (Wave 2)
- In-circuit verification of the encryption relation (Wave 2/3)
- Admin authority rotation (two-step commit/reveal)
- Per-platform admin keys with on-chain delegation
- Merkleized dispute map for cheap light-client verification
- Timelocked emergency review path for stuck disputes
