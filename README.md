# DisputeVault

**Privacy-preserving dispute and claims infrastructure on Midnight Network.**

DisputeVault lets a claimant submit sensitive dispute evidence while keeping
the evidence itself private - encrypted client-side, committed on-chain - and
produces verdicts whose integrity anyone can independently verify.

```
Frontend ──▶ Midnight (Compact contract) ──▶ TS Gateway ──▶ Go Worker
    ▲                                                        │
    └──────────── TS Gateway ──▶ Midnight ◀──────────────────┘
```

- Raw evidence is **never** stored publicly on Midnight. It is encrypted
  client-side and can only be decrypted by the authorized platform
  adjudication worker holding the corresponding private key.
- Evidence and verdict **commitments** are enforced by a ZK circuit, so the
  published outcome is bound to the claimed payload.
- Only the authorized adjudicator can publish verdicts.

> Wave 1 trust model: the adjudication worker is trusted with decrypted
> evidence. See `docs/SECURITY.md` for the honest threat model.

## Workspaces

| Path       | What it is                                                              |
| ---------- | ----------------------------------------------------------------------- |
| `contract/`| Compact contract (`disputevault.compact`) + simulator tests             |
| `sdk/`     | Shared TS library: canonical JSON, wire format, commitments, encryption |
| `gateway/` | TS HTTP service - the only Midnight-aware component (midnight-js 4.x)   |
| `worker/`  | Go adjudication worker (decrypt → validate → adjudicate → publish)      |
| `frontend/`| Vite + React + TS + Tailwind DApp with verification UI                  |
| `docs/`    | PROPOSAL · PROTOCOL · ARCHITECTURE · SECURITY                           |

## Toolchain

| Component              | Version (compatibility matrix, ledger-v8) |
| ---------------------- | ----------------------------------------- |
| Compact toolchain      | `compact` 0.5.1                            |
| Compact compiler       | `compactc` 0.31.1 (language 0.23.0)        |
| Compact runtime        | `@midnight-ntwrk/compact-runtime` 0.16.0   |
| Midnight.js            | `@midnight-ntwrk/midnight-js` 4.x          |
| Ledger                 | ledger-v8 (8.0.x)                          |
| Node                   | ≥ 22 (repo tested on 24)                   |
| Go                     | ≥ 1.22                                     |

Install the Compact toolchain:

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/midnightntwrk/compact/releases/latest/download/compact-installer.sh | sh
compact update 0.31.1
```

## Quick start (local devnet)

```bash
# 1. Local devnet: node + indexer + proof server
docker compose up -d

# 2. Compile the contract + run contract tests
cd contract && npm ci && npm run compact && npm test

# 3. SDK tests (canonicalization, commitments, encryption roundtrip)
cd ../sdk && npm ci && npm test

# 4. Gateway (TS Midnight boundary)
cd ../gateway && npm ci && npm run dev

# 5. Worker (Go adjudicator) — against the gateway
cd ../worker && go test ./... && go run ./cmd/server

# 6. Frontend
cd ../frontend && npm ci && npm run dev
```

See `docs/ARCHITECTURE.md` §6 for the full local stack description.

## The three circuits

| Circuit             | Who          | What it does                                          |
| ------------------- | ------------ | ----------------------------------------------------- |
| `register_platform` | admin        | One-time registration of the platform encryption key  |
| `submit_dispute`    | claimant     | Commits evidence, stores encrypted envelope, allocates id |
| `post_verdict`      | admin only   | Publishes the verdict commitment once, for an existing dispute |

Authorization uses the official Midnight **hash-based authentication**
pattern (`persistentHash` over a witness-provided secret compared against an
authority bound at deployment). `ownPublicKey()` is never used for
authorization - per the current Midnight security documentation.

## Security

Read `docs/SECURITY.md` before operating anything. Highlights:

- Platform key registration is one-time; replacement attempts are rejected
  by the circuit.
- Verdict publication requires an in-circuit proof of the admin secret.
- Dispute ids are allocated from a ledger counter; evidence can never be
  overwritten.
- Oversized payloads are rejected, never truncated.
- The ZK proof proves commitment integrity and authorization — **not** that
  an AI verdict is objectively correct.

## Environment

Copy `.env.example` to `.env` (per workspace as needed) and fill in secrets.
`.env` is git-ignored; never commit real keys.

## Documentation

- `docs/PROPOSAL.md` - problem, solution, vision, roadmap
- `docs/PROTOCOL.md` - exact wire formats, canonicalization, commitments
- `docs/ARCHITECTURE.md` - layers, boundaries, repository layout
- `docs/SECURITY.md` - threat model, attacks, trust assumptions

## License

MIT
