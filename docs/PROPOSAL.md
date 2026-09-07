# DisputeVault -> Proposal

**Privacy-preserving dispute and claims infrastructure**, built on Midnight
Network.

---

## 1. Problem

Modern digital work runs on trust that breaks constantly:

- A freelancer finishes a bounty and the platform "loses" the payment record.
- A grantee delivers the milestone; the reviewer disputes that it was
  delivered.
- A buyer returns an item; the marketplace claims the return never happened.
- A user is wrongly flagged by automated KYC and has no way to *prove* their
  case without handing over their entire life to a database.

In every case the resolution process requires **sensitive evidence** -
payment records, private messages, identity documents, unpublished work -
and today that evidence goes into a **centralized database** controlled by
the counterparty. The claimant must simply *trust* that:

- the evidence is stored securely (it often is not),
- it is not used for purposes beyond the dispute,
- it is not silently altered,
- and the verdict was actually based on the submitted evidence.

There is no independent way to verify any of it. And the obvious alternative
- putting evidence on a public blockchain -> is worse: **the evidence becomes
permanently public**, which is unacceptable for precisely the sensitive data
these disputes involve.

## 2. Solution

DisputeVault separates *what must stay private* from *what must be
verifiable*:

| Private (never on-chain) | Publicly verifiable (on Midnight) |
| --- | --- |
| Raw evidence bundle | Evidence commitment (hash) |
| Detailed claim information | Encrypted evidence envelope |
| Sensitive claimant information | Verdict commitment |
| AI reasoning | Dispute id + status + public metadata |

The claimant's browser canonicalizes the evidence into a small manifest,
hashes it into a **commitment**, encrypts the full manifest to the **platform
adjudicator's public key**, and submits both to a Midnight Compact contract.
The adjudication worker decrypts, validates, adjudicates (with AI
assistance), and publishes a **committed, authorized verdict**.

The result:

> **Sensitive evidence stays private while the integrity of the dispute
> evidence and the verdict is independently verifiable by anyone.**

## 3. Target users

- **Bounty platforms** (rejection disputes: "my valid work was rejected")
- **Freelance marketplaces** (non-payment, scope creep)
- **Grant programs** (milestone claim disputes)
- **E-commerce / marketplaces** (refund and return appeals)
- **Creator platforms** (demonetization and takedown appeals)
- **Insurance and compliance teams** (claims and KYC exception workflows)

Common thread: a *platform* that must adjudicate sensitive claims against
*claimants* who have no reason to trust the platform's backend.

## 4. Product vision

DisputeVault is **not** an AI chatbot for disputes. The AI is a component.
The product is the **infrastructure layer**:

1. **Privacy** - claimants reveal evidence only to the adjudicator, not to
   the world.
2. **Integrity** - evidence and verdicts are committed; nothing can be
   rewritten after the fact.
3. **Authorization** - only the legitimate adjudicator can publish outcomes.
4. **Verifiability** - anyone can check a published verdict against a
   claimed payload without any private data.

Platforms integrate DisputeVault to *demonstrate* fair process; claimants
use it because they no longer need to blindly trust the platform.

## 5. Why privacy matters

Dispute evidence is exactly the data people are least willing to expose:
payment struggles, medical or identity documents, employment records,
unpublished creative work, private conversations. A public dispute ledger
would create a permanent, searchable record of people's worst conflicts.
Privacy is not a feature here - it is the precondition for the product to be
usable at all.

## 6. Why Midnight

Midnight is the only mainstream network designed around this exact split:

- **Compact** contracts run inside zero-knowledge circuits: the contract can
  *enforce* that a commitment was computed over the claimed private data
  without the data ever being revealed.
- **Data protection is the default**: private state stays on the user's
  device; nothing is public unless explicitly disclosed.
- The **hash-based authorization pattern** lets the contract verify an
  adjudicator's authority without revealing identity keys.
- A working TypeScript SDK, wallet, proof server, and local devnet make the
  architecture buildable today.

Ethereum-style transparency chains cannot express "prove I hashed this
secret data" without revealing the data; Midnight's ZK circuits can.

## 7. Architecture (summary)

```
Frontend ──▶ Midnight (Compact contract) ──▶ TS Gateway ──▶ Go Worker
    ▲                                                        │
    └──────────── TS Gateway ──▶ Midnight ◀──────────────────┘
```

- **Compact contract** - privacy + authorization (one-time platform
  registration, dispute submission, authorized verdict publication).
- **Go worker** - off-chain adjudication: decrypt → validate → adjudicate →
  canonicalize → publish.
- **TypeScript gateway** - the only Midnight-aware service; HTTP boundary
  for the worker.
- **Frontend** - claimant flow and the public verification interface.

Full details: `ARCHITECTURE.md`. Data formats: `PROTOCOL.md`. Threat model:
`SECURITY.md`.

## 8. Wave 1 scope

In scope:

- One platform, one admin authority, one adjudication worker
- Evidence manifest v1 (256-byte wire), single dispute type family
- Client-side ECDH (P-256) + AES-256-GCM evidence encryption
- Compact contract: `register_platform`, `submit_dispute`, `post_verdict`
- Go worker with `DemoAdjudicator` (deterministic) + `LLMAdjudicator` (API
  key via env)
- Verification UI for evidence and verdict commitments
- Full test suite including the seven documented attacks

Explicitly out of scope (Wave 2/3): two-party disputes, on-chain reviewer
marketplace, token economics, multi-party arbitration, payment settlement.

## 9. Long-term business potential

The same infrastructure generalizes to any "sensitive claim against an
organization" workflow:

```
bounty disputes → freelance disputes → grant claims → refund claims
→ marketplace appeals → creator disputes → insurance claims
→ compliance workflows → KYC exceptions → employment claims
```

The long-term business is a **privacy-preserving claims infrastructure
layer** sold to organizations that must process sensitive claims while
proving process integrity to regulators, customers, and counterparties.
Commitment-verified dispute outcomes are auditable without exposing the
underlying evidence — a property no centralized ticketing system can offer.

## 10. Roadmap

### Wave 2 -> stronger privacy, two parties
- Two-party disputes (respondent counter-evidence, joint decryption)
- Encrypted *bundles* (multiple evidence artifacts per dispute)
- Envelope ↔ commitment cryptographic binding (AEAD associated data)
- Multiple evidence types beyond the text manifest
- Multiple AI models + agreement scoring; human review queue

### Wave 3 -> decentralization
- Reviewer marketplace with staked arbitration
- Reputation for adjudicators and platforms
- Organization-specific policy packs (versioned, committed on-chain)
- Enterprise APIs, SSO, compliance exports
- Multi-adjudicator consensus with commitment reveal phases
