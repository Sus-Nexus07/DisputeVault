/**
 * DisputeVault simulator test helpers.
 *
 * Runs the compiled Compact contract (`src/managed/disputevault`) directly
 * against `@midnight-ntwrk/compact-runtime` 0.16.0 — the exact runtime the
 * pinned compiler (compactc 0.31.1) codegen targets; see
 * `src/managed/disputevault/compiler/contract-info.json`.
 *
 * Authorization architecture under test (must not be weakened):
 *   admin secret (witness) → adminPk(sk) derived in-circuit via
 *   persistentHash([pad(32, "disputevault:admin:pk"), sk]) → compared against
 *   the constructor-bound `admin_authority`.
 *
 * `ownPublicKey()` is never used for authorization, so no wallet identity is
 * involved anywhere in these tests; the caller slot only swaps the witness
 * secret to simulate an attacker-controlled frontend.
 */
import * as crypto from 'node:crypto';
import * as runtime from '@midnight-ntwrk/compact-runtime';
import {
  Contract,
  ledger,
  type Dispute,
  type DisputeStatus,
  type Ledger,
} from '../managed/disputevault/contract/index.js';

export { ledger };
export type { Dispute, DisputeStatus, Ledger };

/** Fail fast if the installed runtime drifts from the pinned version. */
const RUNTIME_VERSION = '0.16.0';
if (runtime.versionString !== RUNTIME_VERSION) {
  throw new Error(
    `compact-runtime version mismatch: expected ${RUNTIME_VERSION}, got ${runtime.versionString} — ` +
      'the pinned toolchain (compactc 0.31.1 / language 0.23.0) must not drift silently',
  );
}

export const hex = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString('hex');

export const fromHex = (s: string): Uint8Array =>
  Uint8Array.from(Buffer.from(s, 'hex'));

export const bytesOf = (s: string): Uint8Array =>
  Uint8Array.from(Buffer.from(s, 'utf8'));

/** 32 zero bytes — the "no verdict" value. */
export const ZERO32 = new Uint8Array(32);
/** 65 zero bytes — the default (unregistered) platform_enc_key. */
export const ZERO65 = new Uint8Array(65);

/** pad(32, "disputevault:admin:pk") — the in-circuit adminPk domain tag. */
export const ADMIN_PK_TAG: Uint8Array = (() => {
  const tag = bytesOf('disputevault:admin:pk');
  const out = new Uint8Array(32);
  out.set(tag, 0);
  return out;
})();

export const sha256 = (...chunks: Uint8Array[]): Uint8Array =>
  Uint8Array.from(
    crypto
      .createHash('sha256')
      .update(Buffer.concat(chunks.map((c) => Buffer.from(c))))
      .digest(),
  );

/**
 * PROTOCOL.md §12.3 vector: adminPk = SHA256(pad32("disputevault:admin:pk") || sk).
 * Guarded at module load: if the pinned runtime ever stops matching the
 * documented plain-SHA-256 semantics, every test in the suite fails here
 * first with a precise message.
 */
export const VECTOR_ADMIN_SECRET = Uint8Array.from(
  { length: 32 },
  (_, i) => i + 1,
);
export const VECTOR_ADMIN_PK_HEX =
  'b90ec368c58fec263a772c8288ae9143bee84167d2f952eb6ed3bc3ec8ffc212';
{
  const viaRuntime = runtime.persistentHash(
    new runtime.CompactTypeVector(2, new runtime.CompactTypeBytes(32)),
    [ADMIN_PK_TAG, VECTOR_ADMIN_SECRET],
  );
  if (hex(viaRuntime) !== VECTOR_ADMIN_PK_HEX) {
    throw new Error(
      `persistentHash<Vector<2, Bytes<32>>> does not match PROTOCOL.md §12.3: ` +
        `expected ${VECTOR_ADMIN_PK_HEX}, got ${hex(viaRuntime)}`,
    );
  }
  const viaPlain = sha256(ADMIN_PK_TAG, VECTOR_ADMIN_SECRET);
  if (hex(viaPlain) !== VECTOR_ADMIN_PK_HEX) {
    throw new Error(
      'plain SHA-256 no longer reproduces the §12.3 adminPk vector',
    );
  }
}

/** PROTOCOL.md §12.1 evidence commitment vector (canonical JSON, 199 bytes). */
export const VECTOR_EVIDENCE_JSON =
  '{"v":1,"bounty_id":42,"claimant_id_hash":"9f86d081884c7d659a2feaa0c55ad015","type":1,"evidence_ref_hash":"60303ae22b998861bce3b28f33eec1be","summary":"Payment was not received for completed bounty."}';
export const VECTOR_EVIDENCE_COMMITMENT_HEX =
  '7613067b4ffb158b9c025e30eb0d0934f2a51ea483912893b1434e7a5a245a1a';

/** PROTOCOL.md §12.2 verdict commitment vector (canonical JSON, 140 bytes). */
export const VECTOR_VERDICT_JSON =
  '{"v":1,"dispute_id":42,"decision":"claimant_wins","confidence":87,"reason_code":"PAYMENT_NOT_VERIFIED","policy_version":"bounty-dispute-v1"}';
export const VECTOR_VERDICT_COMMITMENT_HEX =
  'e8154db00dd432f5436ac4d66714466d49ca6678ad2aba4b06627123a8e55765';

/**
 * Build a DV1E/DV1V wire exactly as PROTOCOL.md §3:
 * magic (4B) + uint16be(json_len) (2B) + canonical JSON + zero padding.
 */
export function makeWire(
  magic: 'DV1E' | 'DV1V',
  json: string,
  wireSize: number,
): Uint8Array {
  const jsonBytes = bytesOf(json);
  if (jsonBytes.length > 0xffff) {
    throw new Error(
      `canonical JSON exceeds uint16 length: ${jsonBytes.length}`,
    );
  }
  if (6 + jsonBytes.length > wireSize) {
    throw new Error(
      `canonical JSON (${jsonBytes.length} bytes) does not fit ${wireSize}-byte wire`,
    );
  }
  const wire = new Uint8Array(wireSize);
  wire.set(bytesOf(magic), 0);
  wire[4] = (jsonBytes.length >> 8) & 0xff;
  wire[5] = jsonBytes.length & 0xff;
  wire.set(jsonBytes, 6);
  return wire;
}

export const makeEvidenceWire = (json: string): Uint8Array =>
  makeWire('DV1E', json, 256);
export const makeVerdictWire = (json: string): Uint8Array =>
  makeWire('DV1V', json, 192);

/** The §12.1 normative evidence wire. */
export const VECTOR_EVIDENCE_WIRE = makeEvidenceWire(VECTOR_EVIDENCE_JSON);
/** The §12.2 normative verdict wire (bound to dispute 42). */
export const VECTOR_VERDICT_WIRE = makeVerdictWire(VECTOR_VERDICT_JSON);

/**
 * Synthetic 65-byte P-256-style points (0x04 || X || Y) for registration
 * tests. They are format-valid placeholder keys generated locally; the
 * contract only sees opaque bytes.
 */
export function makePlatformKey(seed: number): Uint8Array {
  const key = new Uint8Array(65);
  key[0] = 0x04;
  for (let i = 1; i < 65; i++) {
    key[i] = (seed * 31 + i * 7) & 0xff;
  }
  return key;
}

export const VALID_PLATFORM_KEY = makePlatformKey(1);
export const ATTACKER_PLATFORM_KEY = makePlatformKey(0x5eed);

/** An arbitrary well-formed 284-byte envelope (ciphertext placeholder). */
export function makeEnvelope(seed: number): Uint8Array {
  const env = new Uint8Array(284);
  for (let i = 0; i < env.length; i++) {
    env[i] = (seed * 131 + i * 13) & 0xff;
  }
  return env;
}

export const VALID_ENVELOPE = makeEnvelope(0xab);

/** A generic failure message fragment for `expectCircuitFailure`. */
export const failedAssert = (message: string): RegExp =>
  new RegExp(`failed assert: ${message.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`);

/** Deployment handle; `state` is the current ChargedState of the ledger. */
export interface Deployment {
  /** Mutable witness source — tests swap this to simulate attackers. */
  adminSecret: Uint8Array;
  contract: Contract<null>;
  state: runtime.ChargedState;
}

/** Pre-encoded 32-zero-byte coin public key; irrelevant to authorization. */
const DUMMY_COIN_PK = { bytes: new Uint8Array(32) } as never;

/**
 * Deploy a fresh DisputeVault instance with the given admin secret bound in
 * the constructor. The witness returns the *current* value of the
 * deployment's `adminSecret` slot, so tests simulate an attacker-controlled
 * frontend by reassigning it between circuit calls.
 */
export function deploy(
  adminSecret: Uint8Array = VECTOR_ADMIN_SECRET,
): Deployment {
  const deployment: Deployment = {
    adminSecret,
    contract: undefined as unknown as Contract<null>,
    state: undefined as unknown as runtime.ChargedState,
  };
  const contract = new Contract<null>({
    adminSecret: (context) => {
      void context;
      return [null, deployment.adminSecret];
    },
  });
  const constructorContext = runtime.createConstructorContext(
    null,
    DUMMY_COIN_PK,
  );
  const initial = contract.initialState(constructorContext, adminSecret);
  deployment.contract = contract;
  deployment.state = initial.currentContractState.data;
  return deployment;
}

/**
 * Run a circuit against the deployment's current state and advance the
 * deployment state with the circuit's resulting state. Returns the circuit
 * result value.
 */
function callCircuit(
  deployment: Deployment,
  circuit: string,
  ...args: unknown[]
): unknown {
  const context = runtime.createCircuitContext(
    runtime.dummyContractAddress(),
    DUMMY_COIN_PK,
    deployment.state,
    null,
  );
  const fn = deployment.contract.circuits[
    circuit as keyof typeof deployment.contract.circuits
  ] as unknown as (ctx: never, ...a: unknown[]) => { result: unknown; context: never };
  const res = fn(context as never, ...args);
  deployment.state = (
    res as unknown as { context: { currentQueryContext: { state: runtime.ChargedState } } }
  ).context.currentQueryContext.state;
  return res.result;
}

type CircuitArgs = {
  register_platform: [platformPublicKey: Uint8Array];
  submit_dispute: [evidenceWire: Uint8Array, envelope: Uint8Array];
  post_verdict: [disputeId: bigint, verdictWire: Uint8Array];
};
type CircuitResults = {
  register_platform: void;
  submit_dispute: bigint;
  post_verdict: void;
};

/** Invoke a circuit as the current witness-holder (admin by default). */
export function call<K extends keyof CircuitArgs>(
  deployment: Deployment,
  circuit: K,
  ...args: CircuitArgs[K]
): CircuitResults[K] {
  return callCircuit(deployment, circuit as never, ...args) as CircuitResults[K];
}

/**
 * Expect a circuit call to be rejected. Fails the test if the call succeeds,
 * and (optionally) requires the failure to be the exact assert with the given
 * message — never a generic "something failed".
 */
export function expectCircuitFailure(
  fn: () => unknown,
  expectedAssert?: RegExp,
): string {
  try {
    fn();
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    if (expectedAssert && !expectedAssert.test(message)) {
      throw new Error(
        `circuit failed with an unexpected error.\n  expected: ${expectedAssert.source}\n  actual:   ${message}`,
      );
    }
    return message;
  }
  throw new Error(
    'expected the circuit call to be rejected, but it succeeded — the guard did not fire',
  );
}

/** Read-only ledger view of the deployment's current state. */
export function ledgerView(deployment: Deployment): Ledger {
  return ledger(deployment.state);
}

/** Convenience: look up a dispute record (throws if absent). */
export function getDispute(deployment: Deployment, id: bigint): Dispute {
  return ledgerView(deployment).disputes.lookup(id);
}

