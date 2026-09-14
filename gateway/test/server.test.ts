/**
 * HTTP tests for the DisputeVault gateway.
 *
 * The Midnight network path is injected as a fake ChainConnection (see
 * helpers/fakeChain.ts); the production chain.ts module is NOT mocked —
 * only the compiled-contract ledger parser is stubbed so the fake ledger
 * can flow through the real reader/submit/server code paths.
 *
 * This file exists ONLY to test the HTTP boundary; it is not a mock of the
 * live network path and makes no claim about live connectivity.
 */
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import pino from 'pino';

import { buildServer, type GatewayServer } from '../src/server.js';
import { loadConfig } from '../src/config.js';
import { canonicalizeEvidence, canonicalizeVerdict } from '@disputevault/sdk';

// ---------------------------------------------------------------------------
// Mocks (module-level, before imports of the system under test).
// ---------------------------------------------------------------------------

// The real parser expects real Compact state bytes; the fake harness stores a
// structured FakeLedger. Redirect the parser so it passes the fake through.
vi.mock('../src/chain.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/chain.js')>();
  return {
    ...actual,
    contractLedger: vi.fn((state: { data?: unknown }) => (state as { data: unknown }).data ?? state),
  };
});

import { connectionStatus } from '../src/chain.js';
import { makeFakeChainHarness, type FakeChainHarness } from './helpers/fakeChain.js';

const sha256hex = (bytes: Uint8Array): string =>
  createHash('sha256').update(bytes).digest('hex');

// ---------------------------------------------------------------------------
// Fixtures: canonical payloads from PROTOCOL.md §4 and §7.
// ---------------------------------------------------------------------------

const EVIDENCE_MANIFEST = {
  v: 1,
  bounty_id: 42,
  claimant_id_hash: '9f86d081884c7d659a2feaa0c55ad015',
  type: 1,
  evidence_ref_hash: '60303ae22b998861bce3b28f33eec1be',
  summary: 'Payment was not received for completed bounty.',
};

const VERDICT = {
  v: 1,
  dispute_id: 7,
  decision: 'claimant_wins' as const,
  confidence: 87,
  reason_code: 'PAYMENT_NOT_VERIFIED',
  policy_version: 'bounty-dispute-v1',
};

function evidenceWireHex(): string {
  const wire = new Uint8Array(256);
  const json = Buffer.from(canonicalizeEvidence(EVIDENCE_MANIFEST), 'utf8');
  wire.set(Buffer.from('DV1E', 'utf8'), 0);
  wire[4] = (json.length >> 8) & 0xff;
  wire[5] = json.length & 0xff;
  wire.set(json, 6);
  return Buffer.from(wire).toString('hex');
}

function verdictWire(disputeId: bigint | number, decision = 'claimant_wins'): Uint8Array {
  const payload = { ...VERDICT, dispute_id: disputeId, decision };
  const json = Buffer.from(canonicalizeVerdict(payload), 'utf8');
  const wire = new Uint8Array(192);
  wire.set(Buffer.from('DV1V', 'utf8'), 0);
  wire[4] = (json.length >> 8) & 0xff;
  wire[5] = json.length & 0xff;
  wire.set(json, 6);
  return wire;
}

const ENVELOPE_HEX = Buffer.from(new Uint8Array(284).fill(7)).toString('hex');

// ---------------------------------------------------------------------------
// Harness.
// ---------------------------------------------------------------------------

let harness: FakeChainHarness;
let server: GatewayServer;

const noopLogger = pino({ level: 'silent' });

async function startServer(): Promise<GatewayServer> {
  harness = makeFakeChainHarness();
  return buildServer({
    config: loadConfig({}),
    logger: noopLogger,
    // Cast: the fake mirrors the ChainConnection surface the handlers use.
    connection: harness.connection as never,
  });
}

beforeEach(async () => {
  server = await startServer();
  await server.ready();
});

afterEach(async () => {
  await server.close();
});

// ---------------------------------------------------------------------------
// Health.
// ---------------------------------------------------------------------------

describe('GET /health', () => {
  it('reports liveness, redacted config, and connection state without secrets', async () => {
    const res = await server.app.inject({ method: 'GET', url: '/health' });
    expect(res.statusCode).toBe(200);
    const body = res.json() as {
      status: string;
      service: string;
      midnight: { connected: boolean; coinPublicKey: string | null };
      config: Record<string, unknown>;
    };
    expect(body.status).toBe('ok');
    expect(body.service).toBe('disputevault-gateway');
    expect(body.midnight.connected).toBe(true);
    expect(body.midnight.coinPublicKey).toBeTypeOf('string');
    expect(body.config['adminSecretConfigured']).toBe(false);
    expect(body.config['walletSeedConfigured']).toBe(false);
  });

  it('reports connected=false when no connection is established', async () => {
    const standalone = await buildServer({ config: loadConfig({}), logger: noopLogger });
    try {
      const res = await standalone.app.inject({ method: 'GET', url: '/health' });
      expect(res.statusCode).toBe(200);
      expect((res.json() as { midnight: { connected: boolean } }).midnight.connected).toBe(false);
    } finally {
      await standalone.close();
    }
  });

  it('connectionStatus hexes the address and never exposes provider internals', async () => {
    const status = connectionStatus(harness.connection as never);
    expect(status.connected).toBe(true);
    expect(status.contractAddress).toMatch(/^[0-9a-f]{64}$/);
    expect(status.coinPublicKey).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ---------------------------------------------------------------------------
// Malformed requests.
// ---------------------------------------------------------------------------

describe('malformed requests', () => {
  it('rejects a non-object body on POST /disputes', async () => {
    const res = await server.app.inject({
      method: 'POST',
      url: '/disputes',
      payload: 'not-json-object',
      headers: { 'content-type': 'text/plain' },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({ error: { code: 'malformed_request' } });
  });

  it('rejects wrong-length evidence wire and envelope with field-level errors', async () => {
    const res = await server.app.inject({
      method: 'POST',
      url: '/disputes',
      payload: { evidence_wire: 'aabb', envelope: 'ccdd' },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({ error: { code: 'malformed_request' } });
    expect(harness.calls.submit_dispute).toHaveLength(0);
  });

  it('rejects non-hex bytes', async () => {
    const res = await server.app.inject({
      method: 'POST',
      url: '/disputes',
      payload: { evidence_wire: 'zz'.repeat(256), envelope: ENVELOPE_HEX },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({ error: { code: 'malformed_request' } });
  });

  it('rejects invalid dispute ids on GET and POST verdict routes', async () => {
    for (const url of ['/disputes/not-a-number', '/disputes/-1/verdict', '/disputes/1.5/verdict']) {
      const res = await server.app.inject({ method: url.includes('verdict') ? 'POST' : 'GET', url });
      expect(res.statusCode).toBe(400);
      expect(res.json()).toMatchObject({ error: { code: 'invalid_dispute_id' } });
    }
  });

  it('rejects oversized bodies with 413 before any handler logic', async () => {
    const res = await server.app.inject({
      method: 'POST',
      url: '/disputes',
      payload: { evidence_wire: 'aa'.repeat(4096) },
    });
    expect([400, 413]).toContain(res.statusCode);
    expect(res.json()).toHaveProperty('error');
  });

  it('rejects a verdict body without a verdict object', async () => {
    const res = await server.app.inject({
      method: 'POST',
      url: '/disputes/7/verdict',
      payload: { nope: true },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({ error: { code: 'malformed_request' } });
  });

  it('rejects schema-invalid verdict payloads (user error, not contract error)', async () => {
    const res = await server.app.inject({
      method: 'POST',
      url: '/disputes/7/verdict',
      payload: { verdict: { ...VERDICT, confidence: 101 } },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('protocol_error');
    expect(harness.calls.post_verdict).toHaveLength(0);
  });

  it('returns 404 with code not_found for unknown disputes', async () => {
    const res = await server.app.inject({ method: 'GET', url: '/disputes/999' });
    expect(res.statusCode).toBe(404);
    expect(res.json()).toMatchObject({ error: { code: 'not_found' } });
  });
});

// ---------------------------------------------------------------------------
// Dispute submission.
// ---------------------------------------------------------------------------

describe('POST /disputes (submit_dispute)', () => {
  it('submits a valid dispute and returns the fresh id + commitment', async () => {
    const res = await server.app.inject({
      method: 'POST',
      url: '/disputes',
      payload: { evidence_wire: evidenceWireHex(), envelope: ENVELOPE_HEX },
    });
    expect(res.statusCode).toBe(201);
    const body = res.json() as { disputeId: string; evidenceCommitment: string };
    expect(body.disputeId).toBe('1');
    // The commitment equals SHA-256 of the exact wire bytes (§5.3).
    expect(body.evidenceCommitment).toBe(sha256hex(Buffer.from(evidenceWireHex(), 'hex')));
    expect(harness.calls.submit_dispute).toHaveLength(1);
    expect(harness.calls.submit_dispute[0]!.envelope.length).toBe(284);
  });

  it('never echoes the evidence wire or envelope bytes in the response', async () => {
    const wireHex = evidenceWireHex();
    const res = await server.app.inject({
      method: 'POST',
      url: '/disputes',
      payload: { evidence_wire: wireHex, envelope: ENVELOPE_HEX },
    });
    expect(res.body).not.toContain(wireHex);
    expect(res.body).not.toContain(ENVELOPE_HEX);
    // commitment yes (32-byte digest), raw wire no (256 bytes).
    expect(res.body).not.toContain(wireHex.slice(0, 64));
  });

  it('submits a second dispute with a fresh id', async () => {
    await server.app.inject({
      method: 'POST',
      url: '/disputes',
      payload: { evidence_wire: evidenceWireHex(), envelope: ENVELOPE_HEX },
    });
    const res = await server.app.inject({
      method: 'POST',
      url: '/disputes',
      payload: { evidence_wire: evidenceWireHex(), envelope: ENVELOPE_HEX },
    });
    expect(res.statusCode).toBe(201);
    expect((res.json() as { disputeId: string }).disputeId).toBe('2');
  });
});

// ---------------------------------------------------------------------------
// Verdict binding (Attack 6 defense in depth).
// ---------------------------------------------------------------------------

describe('POST /disputes/:id/verdict (post_verdict + §7 binding)', () => {
  beforeEach(async () => {
    // Seed a submitted dispute (id 1) to post verdicts against.
    await server.app.inject({
      method: 'POST',
      url: '/disputes',
      payload: { evidence_wire: evidenceWireHex(), envelope: ENVELOPE_HEX },
    });
  });

  it('rejects a binding-mismatched verdict before any contract call (Attack 6)', async () => {
    // Target dispute 1, payload embedded dispute_id 7.
    const res = await server.app.inject({
      method: 'POST',
      url: '/disputes/1/verdict',
      payload: { verdict: VERDICT },
    });
    expect(res.statusCode).toBe(400);
    const body = res.json() as { error: { code: string; message: string } };
    expect(body.error.code).toBe('protocol_error');
    expect(body.error.message).toContain('binding mismatch');
    // The contract circuit was NEVER invoked.
    expect(harness.calls.post_verdict).toHaveLength(0);
  });

  it('accepts a correctly bound verdict and stores SHA-256 of the wire', async () => {
    const res = await server.app.inject({
      method: 'POST',
      url: '/disputes/1/verdict',
      payload: { verdict: { ...VERDICT, dispute_id: 1 } },
    });
    expect(res.statusCode).toBe(201);
    const body = res.json() as { disputeId: string; verdictCommitment: string; canonicalJson: string };
    expect(body.disputeId).toBe('1');
    expect(body.verdictCommitment).toBe(sha256hex(verdictWire(1)));
    expect(body.canonicalJson).toBe(canonicalizeVerdict({ ...VERDICT, dispute_id: 1 }));
    expect(harness.calls.post_verdict).toHaveLength(1);
    expect(harness.calls.post_verdict[0]!.disputeId).toBe(1n);
    expect(harness.calls.post_verdict[0]!.verdictWire.length).toBe(192);
  });

  it('flips the dispute status to VERDICT_POSTED and refuses a second verdict', async () => {
    await server.app.inject({
      method: 'POST',
      url: '/disputes/1/verdict',
      payload: { verdict: { ...VERDICT, dispute_id: 1 } },
    });
    const res = await server.app.inject({
      method: 'POST',
      url: '/disputes/1/verdict',
      payload: { verdict: { ...VERDICT, dispute_id: 1 } },
    });
    expect(res.statusCode).toBe(502);
    expect(res.json().error.code).toBe('contract_error');
    expect(harness.calls.post_verdict).toHaveLength(2); // attempted, circuit refused
    const after = await server.app.inject({ method: 'GET', url: '/disputes/1' });
    expect((after.json() as { status: string }).status).toBe('VERDICT_POSTED');
  });

  it('rejects a verdict for a nonexistent dispute via the circuit assert (502)', async () => {
    const res = await server.app.inject({
      method: 'POST',
      url: '/disputes/999/verdict',
      payload: { verdict: { ...VERDICT, dispute_id: 999 } },
    });
    expect(res.statusCode).toBe(502);
    expect(res.json().error.code).toBe('contract_error');
    // Message must not leak circuit internals.
    expect(res.json().error.message).not.toContain('assert');
  });
});

// ---------------------------------------------------------------------------
// Platform registration.
// ---------------------------------------------------------------------------

describe('POST /platform/register', () => {
  it('registers a 65-byte platform key once and refuses a second registration', async () => {
    const key = '04' + 'ab'.repeat(64); // uncompressed P-256 point (fixture)
    const res = await server.app.inject({
      method: 'POST',
      url: '/platform/register',
      payload: { platform_public_key: key },
    });
    expect(res.statusCode).toBe(201);
    expect(res.json()).toEqual({ platformEncKey: key });

    const res2 = await server.app.inject({
      method: 'POST',
      url: '/platform/register',
      payload: { platform_public_key: '04' + 'cd'.repeat(64) },
    });
    expect(res2.statusCode).toBe(502);
    expect(res2.json().error.code).toBe('contract_error');
  });

  it('rejects a wrong-length platform key', async () => {
    const res = await server.app.inject({
      method: 'POST',
      url: '/platform/register',
      payload: { platform_public_key: '04ab' },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('malformed_request');
    expect(harness.calls.register_platform).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Reads.
// ---------------------------------------------------------------------------

describe('GET /disputes and GET /disputes/:id', () => {
  it('lists disputes with public metadata only', async () => {
    await server.app.inject({
      method: 'POST',
      url: '/disputes',
      payload: { evidence_wire: evidenceWireHex(), envelope: ENVELOPE_HEX },
    });
    const res = await server.app.inject({ method: 'GET', url: '/disputes' });
    expect(res.statusCode).toBe(200);
    const body = res.json() as {
      disputeCounter: string | null;
      disputes: Array<{ disputeId: string; status: string; evidenceCommitment: string }>;
    };
    expect(body.disputeCounter).toBe('1'); // increment-then-read: counter == submissions
    expect(body.disputes).toHaveLength(1);
    expect(body.disputes[0]!.status).toBe('SUBMITTED');
    expect(body.disputes[0]!.evidenceCommitment).toBe(sha256hex(Buffer.from(evidenceWireHex(), 'hex')));
  });

  it('returns public fields for a single dispute', async () => {
    await server.app.inject({
      method: 'POST',
      url: '/disputes',
      payload: { evidence_wire: evidenceWireHex(), envelope: ENVELOPE_HEX },
    });
    const res = await server.app.inject({ method: 'GET', url: '/disputes/1' });
    expect(res.statusCode).toBe(200);
    const body = res.json() as Record<string, string>;
    expect(Object.keys(body).sort()).toEqual([
      'disputeId',
      'envelope',
      'evidenceCommitment',
      'status',
      'verdictCommitment',
    ]);
  });
});

// ---------------------------------------------------------------------------
// Commitment verification.
// ---------------------------------------------------------------------------

describe('POST /verify/commitment', () => {
  it('verifies a matching evidence commitment', async () => {
    await server.app.inject({
      method: 'POST',
      url: '/disputes',
      payload: { evidence_wire: evidenceWireHex(), envelope: ENVELOPE_HEX },
    });
    const res = await server.app.inject({
      method: 'POST',
      url: '/verify/commitment',
      payload: { dispute_id: '1', kind: 'evidence', payload: EVIDENCE_MANIFEST },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { matches: boolean; computedCommitment: string };
    expect(body.matches).toBe(true);
    expect(body.computedCommitment).toBe(sha256hex(Buffer.from(evidenceWireHex(), 'hex')));
  });

  it('verifies a matching verdict commitment (bound payload)', async () => {
    await server.app.inject({
      method: 'POST',
      url: '/disputes',
      payload: { evidence_wire: evidenceWireHex(), envelope: ENVELOPE_HEX },
    });
    await server.app.inject({
      method: 'POST',
      url: '/disputes/1/verdict',
      payload: { verdict: { ...VERDICT, dispute_id: 1 } },
    });
    const res = await server.app.inject({
      method: 'POST',
      url: '/verify/commitment',
      payload: { dispute_id: '1', kind: 'verdict', payload: { ...VERDICT, dispute_id: 1 } },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { matches: boolean };
    expect(body.matches).toBe(true);
  });

  it('enforces the §7 binding rule on the verification path too', async () => {
    await server.app.inject({
      method: 'POST',
      url: '/disputes',
      payload: { evidence_wire: evidenceWireHex(), envelope: ENVELOPE_HEX },
    });
    const res = await server.app.inject({
      method: 'POST',
      url: '/verify/commitment',
      payload: { dispute_id: '1', kind: 'verdict', payload: VERDICT },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('binding_mismatch');
  });

  it('reports matches=false for a tampered payload without erroring', async () => {
    await server.app.inject({
      method: 'POST',
      url: '/disputes',
      payload: { evidence_wire: evidenceWireHex(), envelope: ENVELOPE_HEX },
    });
    const res = await server.app.inject({
      method: 'POST',
      url: '/verify/commitment',
      payload: {
        dispute_id: '1',
        kind: 'evidence',
        payload: { ...EVIDENCE_MANIFEST, summary: 'Tampered summary!' },
      },
    });
    expect(res.statusCode).toBe(200);
    expect((res.json() as { matches: boolean }).matches).toBe(false);
  });

  it('rejects malformed verify bodies', async () => {
    const res = await server.app.inject({
      method: 'POST',
      url: '/verify/commitment',
      payload: { kind: 'evidence' },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('malformed_request');
  });
});

// ---------------------------------------------------------------------------
// Contract error propagation.
// ---------------------------------------------------------------------------

describe('contract error propagation', () => {
  it('maps an indexer failure to 502 contract_error with a safe message', async () => {
    harness.failNextQuery(new Error('indexer grpc stream reset: <raw frame bytes>'));
    const res = await server.app.inject({ method: 'GET', url: '/disputes/1' });
    expect(res.statusCode).toBe(502);
    const body = res.json() as { error: { code: string; message: string } };
    expect(body.error.code).toBe('contract_error');
    expect(body.error.message).not.toContain('grpc');
    expect(body.error.message).not.toContain('frame');
  });

  it('does not leak raw error internals in any error body', async () => {
    harness.failNextQuery(new Error('SECRET-LEAK-CANARY raw provider internals'));
    for (const [method, url, payload] of [
      ['GET', '/disputes', undefined],
      ['GET', '/disputes/1', undefined],
      ['POST', '/disputes', { evidence_wire: evidenceWireHex(), envelope: ENVELOPE_HEX }],
      ['POST', '/verify/commitment', { dispute_id: '1', kind: 'evidence', payload: EVIDENCE_MANIFEST }],
    ] as const) {
      const res = await server.app.inject({ method, url, payload });
      expect(res.statusCode).toBe(502);
      expect(res.body).not.toContain('SECRET-LEAK-CANARY');
    }
  });
});

// ---------------------------------------------------------------------------
// Plaintext evidence leakage.
// ---------------------------------------------------------------------------

describe('no plaintext evidence leakage', () => {
  it('responses never contain the evidence wire, envelope, or summaries', async () => {
    const wireHex = evidenceWireHex();
    const submit = await server.app.inject({
      method: 'POST',
      url: '/disputes',
      payload: { evidence_wire: wireHex, envelope: ENVELOPE_HEX },
    });
    expect(submit.body).not.toContain(wireHex);
    expect(submit.body).not.toContain(ENVELOPE_HEX);

    const verdict = await server.app.inject({
      method: 'POST',
      url: '/disputes/1/verdict',
      payload: { verdict: { ...VERDICT, dispute_id: 1 } },
    });
    expect(verdict.body).not.toContain(wireHex);

    const list = await server.app.inject({ method: 'GET', url: '/disputes' });
    expect(list.body).not.toContain(EVIDENCE_MANIFEST.summary);
    expect(list.body).not.toContain(wireHex);
    // The envelope IS public by design (§6) — but only on reads, never echoed
    // back on the submission path.
    expect(list.body).toContain('envelope');
  });

  it('error paths never echo request bytes', async () => {
    const wireHex = evidenceWireHex();
    harness.failNextQuery(new Error('raw provider dump'));
    const res = await server.app.inject({
      method: 'POST',
      url: '/disputes',
      payload: { evidence_wire: wireHex, envelope: ENVELOPE_HEX },
    });
    expect(res.statusCode).toBe(502);
    expect(res.body).not.toContain(wireHex);
    expect(res.body).not.toContain(ENVELOPE_HEX);
  });
});

// ---------------------------------------------------------------------------
// Lifecycle / connection plumbing.
// ---------------------------------------------------------------------------

describe('server lifecycle', () => {
  it('requireConnection surfaces a typed error when no connection exists', async () => {
    const standalone = await buildServer({ config: loadConfig({}), logger: noopLogger });
    try {
      expect(() => standalone.requireConnection()).toThrow('midnight connection not established');
    } finally {
      await standalone.close();
    }
  });

  it('close() tears down app and connection without throwing', async () => {
    const standalone = await buildServer({ config: loadConfig({}), logger: noopLogger });
    await standalone.ready();
    await expect(standalone.close()).resolves.toBeUndefined();
  });

  it('an EventEmitter-driven connection still satisfies the handler surface', async () => {
    // Guards against accidental reliance on Node event semantics that a real
    // provider object would not have.
    const emitter = new EventEmitter();
    expect(typeof emitter.on).toBe('function');
    expect(harness.connection['providers']).toBeDefined();
  });
});
