# DisputeVault -> Architecture

> **Go performs off-chain adjudication. Compact enforces privacy and
> authorization. TypeScript provides the Midnight chain boundary.**

---

## 1. System diagram

```
                         CLAIMANT
                            │
                            ▼
                   ┌─────────────────┐
                   │    FRONTEND     │  React + Vite + TS + Tailwind
                   │                 │  build evidence manifest
                   │ Build evidence  │  canonicalize + hash
                   │ Encrypt locally │  encrypt envelope (platform pk)
                   └────────┬────────┘
                            │ submit_dispute tx
                            ▼
                    ┌───────────────┐
                    │    MIDNIGHT   │  Compact contract (ledger-v8)
                    │               │  evidence commitment + envelope
                    │ Compact       │  dispute status map
                    │ Contract      │
                    └───────┬───────┘
                            │ encrypted evidence
                            ▼
                     ┌──────────────┐
                     │   GO WORKER  │  decrypt (platform sk)
                     │              │  validate manifest
                     │ decrypt      │  adjudicate (Adjudicator iface)
                     │ validate     │  canonicalize verdict
                     │ adjudicate   │  hash commitment
                     │ LLM          │
                     │ canonicalize │
                     └──────┬───────┘
                            │ HTTP (internal)
                            ▼
                 ┌────────────────────┐
                 │ TS MIDNIGHT GATEWAY│  midnight-js 4.x
                 │                    │  wallet + proving + txs
                 │ Midnight SDK       │
                 │ proving            │
                 │ transactions       │
                 └──────────┬─────────┘
                            │
                            ▼
                         MIDNIGHT
                            │
                            ▼
                       VERIFICATION
                 (frontend /verify re-hashes
                  payloads against on-chain
                  commitments)
```

---

## 2. Repository layout

```
DisputeVault/
├── contract/            Compact contract + compiled artifacts + simulator tests
│   ├── src/
│   │   ├── disputevault.compact
│   │   ├── index.ts         CompiledContract wrapper
│   │   ├── witnesses.ts     adminSecret witness + private state
│   │   ├── managed/         compactc output (generated, committed)
│   │   └── test/            simulator tests incl. the 7 attack tests
│   ├── package.json
│   └── tsconfig.json
│
├── sdk/                 Shared TS library (used by gateway AND frontend)
│   └── src/
│       ├── canonical.ts     canonical JSON serializer (evidence + verdict)
│       ├── wire.ts          DV1E/DV1V wire framing + size limits
│       ├── crypto.ts        SHA-256 commitments + ECDH/AES-GCM envelope
│       ├── keys.ts          P-256 keypair generation/serialization
│       ├── publish.ts       verdict publishing with the OFF-CHAIN verdict/
│       │                    dispute binding check (SECURITY.md §5.1): a
│       │                    mismatched payload is rejected before the
│       │                    contract's post_verdict circuit is ever called
│       └── index.ts
│
├── gateway/             TS service: the ONLY component that talks to Midnight
│   └── src/
│       ├── server.ts        HTTP API (Fastify)
│       ├── chain.ts         midnight-js providers + contract instance
│       ├── reader.ts        ledger reads (disputes, counter, platform key)
│       └── submit.ts        transaction construction + submission
│
├── worker/              Go adjudication worker
│   ├── cmd/server/main.go
│   └── internal/
│       ├── config/          env config
│       ├── decrypt/         envelope decryption (P-256 + AES-GCM)
│       ├── canonical/       canonical JSON + wire (mirror of sdk/)
│       ├── verdict/         Adjudicator iface: Demo + LLM implementations
│       └── chainclient/     HTTP client for the TS gateway
│
├── frontend/            Vite + React + TS + Tailwind DApp
│   └── src/
│       ├── components/  pages/  routes/  lib/  crypto/
│
├── docs/                PROPOSAL / PROTOCOL / ARCHITECTURE / SECURITY
├── .github/workflows/   CI: compile, typecheck, test each workspace
├── docker-compose.yml   local devnet: node + indexer + proof server
├── README.md
└── .env.example
```

---

## 3. Layers and why each boundary exists

### 3.1 Frontend -> Midnight (direct via wallet / DApp connector)

The claimant's browser builds the canonical evidence manifest, computes the
commitment locally, encrypts the envelope **client-side**, and submits the
`submit_dispute` transaction through the user's wallet.

**Why:** the claimant must never hand plaintext evidence to any server. If the
frontend sent plaintext anywhere - even to our own gateway - the privacy
guarantee would collapse into "trust the operator".

### 3.2 Midnight → Go worker (via TS gateway read API)

The worker polls the gateway for disputes in `SUBMITTED` status, fetches the
encrypted envelope, decrypts it with the platform private key, and re-verifies
the evidence commitment.

**Why:** Midnight transaction/proving tooling is TypeScript-based
(`@midnight-ntwrk/*`). There is no native Go SDK. Rather than pretend one
exists, the architecture isolates *all* Midnight specifics behind the gateway
and gives Go a plain HTTP interface.

### 3.3 Go worker -> TS gateway -> Midnight (publish path)

After adjudication, the worker canonicalizes the verdict, hashes it, and asks
the gateway to publish `post_verdict`.

**Why the split:** adjudication policy, LLM integration, and evidence handling
are business logic that changes often and benefits from Go's deployment story.
Chain interaction (proof generation, wallet balancing, tx submission) is
fragile, TypeScript-heavy, and changes with Midnight releases. Separating them
means Midnight SDK upgrades never touch adjudication code and vice versa.

### 3.4 Verification path

Verifiers (frontend `/verify` page, external auditors) never need private
keys. They take a claimed canonical payload, re-canonicalize, re-hash, and
compare against the on-chain commitment read through the gateway (or directly
from an indexer).

**Why:** independent verifiability is the product. The verification path is
deliberately stateless and key-free.

---

## 4. Contract state (Compact ledger)

```
ledger admin_authority:      Bytes<32>            bound at deployment
ledger platform_enc_key:     Bytes<65>            set once by register_platform
ledger dispute_counter:      Counter              next dispute id
ledger disputes:             Map<Uint<64>, Dispute>   id → record

struct Dispute {
  evidence_commitment: Bytes<32>;
  envelope:            Bytes<284>;
  verdict_commitment:  Bytes<32>;
  status:              DisputeStatus;         // SUBMITTED | VERDICT_POSTED
}
```

Circuits:

| Circuit            | Auth                | Guards                                        |
| ------------------ | ------------------- | --------------------------------------------- |
| `register_platform`| admin (hash-based)  | one-time (platform key must be default/zero)  |
| `submit_dispute`   | open (claimant)     | fresh id from counter; no overwrite possible  |
| `post_verdict`     | admin (hash-based)  | dispute exists; verdict not already posted    |

---

## 5. Trust boundaries (Wave 1)

| Component            | Trusted with                                  |
| -------------------- | --------------------------------------------- |
| Claimant browser     | its own evidence (plaintext never leaves)     |
| Go worker            | decrypted evidence (Wave 1 trust assumption)  |
| TS gateway           | tx construction; never sees plaintext evidence|
| Midnight ledger      | public commitments + envelopes only           |
| LLM adjudicator      | recommendation only; verdict reviewed before posting |

Details and threat analysis: `SECURITY.md`.

---

## 6. Local development stack

`docker-compose.yml` runs the reference devnet (node, indexer, proof server -
the images matching the ledger-v8 compatibility matrix). The gateway and
worker run as ordinary processes against it; the frontend runs with Vite.

The worker's `DemoAdjudicator` makes deterministic verdicts for local testing
so the full flow works without an LLM API key.
