# DisputeVault → Deviations & Design Decisions

A running record of decisions that deviate from earlier drafts, from generic
Midnight examples, or from what tooling would do by default. Each entry states
what changed, why, and what enforces it.

---

## D-1. Authorization: witness secret → in-circuit derivation → constructor-bound authority

**Status:** confirmed (replaces an earlier `ownPublicKey()`-based design)

**What:** admin authorization in `register_platform` and `post_verdict` works
as follows:

```
admin secret (private witness, adminSecret())
        │  in-circuit: adminPk(sk) = persistentHash([pad(32,"disputevault:admin:pk"), sk])
        ▼
assert(adminPk(sk) == admin_authority)      // admin_authority bound in constructor
```

**Why it replaced `ownPublicKey()`:** the current Midnight security
documentation explicitly warns:

> Never use `ownPublicKey()` for verification of the caller of a particular
> Compact circuit. `ownPublicKey()` is technically a witness function and each
> user frontend is capable of producing a malicious return from an
> `ownPublicKey()` call.

`ownPublicKey()` returns a *witness-supplied* value, so a malicious frontend
can fake any caller identity; it proves nothing about who invoked the circuit.
The hash-based pattern instead binds authorization to *knowledge of a secret*:
the secret never becomes public, its derivation happens inside the circuit,
and the comparison target is fixed at deployment (no circuit can rewrite
`admin_authority`).

**Enforced by:**

- Constructor: `admin_authority = disclose(adminPk(admin_secret))` — the only
  write to that ledger cell.
- `register_platform` / `post_verdict`: first statement is the in-circuit
  authorization assert (`register_platform: unauthorized` /
  `post_verdict: unauthorized`).
- Simulator tests: `contract/src/test/security.test.ts` proves a wrong (even
  one-bit-different) witness secret is rejected with the exact assert, and
  `contract/src/test/contract.test.ts` proves the bound authority equals the
  PROTOCOL.md §12.3 offline derivation. Mutation testing (flip the in-circuit
  comparison into a tautology) fails 8 tests.

`ownPublicKey()` is **not used anywhere** for authorization, and must not be
reintroduced.

---

## D-2. Commitments: `persistentHash` (SHA-256) over fixed-size wires

**Status:** confirmed (resolves the Keccak/SHA-256 / `persistentHash` /
`persistentCommit` ambiguity)

**What:** every commitment is `persistentHash` over the exact fixed-size wire
bytes (`Bytes<256>` evidence, `Bytes<192>` verdict); the admin derivation is
`persistentHash` over a `Vector<2, Bytes<32>>`. No `persistentCommit`
(keyed/hiding) variant is used, and no Keccak is introduced.

**Why:** the pinned toolchain (compactc 0.31.1, language 0.23.0) exposes
`persistentHash` / `persistentCommit` / `transientHash`; `keccak256` does not
exist in the language-0.23 standard library. `persistentHash` is documented to
use the SHA-256 compression function and to persist across contract upgrades,
which makes commitments reproducible off-chain as plain SHA-256 over
explicitly constructed byte strings (PROTOCOL.md §5.1, verified byte-for-byte
against `@midnight-ntwrk/compact-runtime` 0.16.0). Commitments in Wave 1 are
intentionally binding but not hiding; payloads are meant to be publishable
for independent verification.

**Enforced by:** normative vectors in PROTOCOL.md §12 and the suite
`contract/src/test/protocol-vectors.test.ts`, which re-checks the runtime
against the vectors on every test run (a toolchain drift fails the suite
before any behavior test runs).

---

## D-3. Envelope ↔ commitment binding is off-chain in Wave 1 (documented gap)

**Status:** accepted limitation, not a deviation to fix silently

**What:** the circuit proves the *witness plaintext* hashes to the stored
commitment and stores the envelope, but cannot verify that the envelope
encrypts that same plaintext (P-256/AES-GCM are not in-circuit provable).

**Why:** closing it properly (AEAD associated data binding, or in-circuit
encryption proof) is Wave 2 scope. Pretending otherwise would be a false
security claim.

**Enforced by:** the worker must decrypt, re-canonicalize, re-hash, and
compare against the on-chain commitment before adjudicating; mismatch is
escalated to `needs_human_review`. See SECURITY.md §6.

---

## D-4. Verdict `dispute_id` binding enforced off-chain (PROTOCOL.md §7)

**Status:** confirmed

**What:** `post_verdict` takes the outer `dispute_id` and the private verdict
wire, but the circuit cannot parse JSON, so it cannot check that the payload's
`dispute_id` field equals the outer id. The binding check is therefore
implemented in the SDK: `publishVerdict` rejects a mismatched payload before
any contract interaction (see SECURITY.md §5.1 for the Wave-1 trust boundary
this represents).

**Why:** Compact has no JSON parsing in-circuit; moving canonical JSON into
the circuit is out of scope for Wave 1.

**Enforced by:** the SDK (`sdk/src/publish.ts` — the single gate every
publisher must pass; tested in `sdk/test/publish.test.ts`, which proves the
contract circuit is not invoked on mismatch), plus defense in depth by every
off-chain publisher (worker derives the id from the fetched dispute record —
the caller-supplied id is never trusted; gateway re-checks before constructing
the transaction; verification UI re-checks) and by the contract tests, which
pin the publisher rule and prove a mismatched payload never reaches the ledger
(`contract/src/test/security.test.ts`, "Attack 6").
