/**
 * DisputeVault gateway HTTP API (docs/ARCHITECTURE.md §2 `server.ts`).
 *
 * Fastify service exposing the Wave-1 surface:
 *
 *   GET  /health                 liveness + Midnight connection status
 *   GET  /disputes               public chain metadata + dispute list
 *   GET  /disputes/:id           one dispute's public metadata
 *   POST /disputes               submit_dispute (opaque wire + envelope)
 *   POST /disputes/:id/verdict   post_verdict (SDK binding check enforced)
 *   POST /platform/register      register_platform (admin)
 *   POST /verify/commitment      commitment/status verification helper
 *
 * Security posture (docs/SECURITY.md):
 *   - the gateway never receives plaintext evidence; requests carry only
 *     commitments, the DV1E wire (public to the ledger), and envelopes;
 *   - error responses never echo request bytes, secrets, or stack traces;
 *   - private keys never appear in configuration output or responses.
 */
import Fastify, {
  type FastifyInstance,
  type FastifyReply,
  type FastifyRequest,
} from 'fastify';
import type { Logger } from 'pino';

import {
  ProtocolError,
  validateVerdict,
  evidenceCommitment,
  verdictCommitment,
  type VerdictV1,
} from '@disputevault/sdk';
import {
  connectContract,
  connectionStatus,
  type ChainConnection,
} from './chain.js';
import {
  fetchChainMetadata,
  fetchDispute,
  listDisputes,
} from './reader.js';
import {
  registerPlatform,
  submitDispute,
  submitVerdict,
} from './submit.js';
import {
  loadConfig,
  publicConfigView,
  type GatewayConfig,
} from './config.js';

const MAX_BODY_BYTES = 16 * 1024; // all payloads are tiny fixed-size frames

/** Error body shape: stable machine-readable code, safe message. */
interface ErrorBody {
  error: { code: string; message: string };
}

/** Map any thrown error to (statusCode, code, safeMessage). */
function errorView(e: unknown): { statusCode: number; code: string; message: string } {
  if (e instanceof ProtocolError) {
    return { statusCode: 400, code: 'protocol_error', message: e.message };
  }
  const anyErr = e as { statusCode?: number; code?: string; message?: string };
  if (typeof anyErr?.statusCode === 'number' && typeof anyErr?.code === 'string') {
    return {
      statusCode: anyErr.statusCode,
      code: anyErr.code,
      message: anyErr.message ?? 'request failed',
    };
  }
  // Contract/indexer/wallet errors: propagate a failure signal WITHOUT raw
  // internals (which can embed transaction payloads).
  return {
    statusCode: 502,
    code: 'contract_error',
    message: 'midnight interaction failed; see gateway logs for details',
  };
}

function sendError(reply: FastifyReply, e: unknown): FastifyReply {
  const view = errorView(e);
  const body: ErrorBody = { error: { code: view.code, message: view.message } };
  return reply.status(view.statusCode).send(body);
}

/** Parse a decimal dispute id (Uint<64>); null when malformed. */
function parseDisputeId(raw: string): bigint | null {
  if (!/^[0-9]+$/.test(raw)) return null;
  const id = BigInt(raw);
  if (id < 0n || id >= 1n << 64n) return null;
  return id;
}

/** Decode a hex byte string; null when malformed or wrong length. */
function parseHexBytes(raw: unknown, expectedLen: number): Uint8Array | null {
  if (typeof raw !== 'string') return null;
  const hex = raw.trim().toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]*$/.test(hex) || hex.length !== expectedLen * 2) return null;
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

export interface BuildServerOptions {
  readonly config: GatewayConfig;
  readonly logger: Logger;
  /** Injected connection (tests); otherwise connectContract is used lazily. */
  readonly connection?: ChainConnection;
}

export interface GatewayServer {
  readonly app: FastifyInstance;
  readonly ready: () => Promise<void>;
  readonly close: () => Promise<void>;
  /** Resolve the chain connection (throws when not configured). */
  readonly requireConnection: () => ChainConnection;
}

export async function buildServer(opts: BuildServerOptions): Promise<GatewayServer> {
  const { config, logger } = opts;
  let connection: ChainConnection | undefined = opts.connection;
  let connecting: Promise<ChainConnection> | undefined;

  // Cast to the default-generic FastifyInstance once here: the instance is
  // parameterized with our pino Logger, the public surface uses Fastify's
  // FastifyBaseLogger (a structural supertype for logging purposes).
  const app = Fastify({
    loggerInstance: logger,
    bodyLimit: MAX_BODY_BYTES,
    // Do not include stack traces or the full request in error payloads.
    genReqId: () => crypto.randomUUID(),
  }) as unknown as FastifyInstance;

  // --- helpers -------------------------------------------------------------

  function requireConnection(): ChainConnection {
    if (!connection) {
      const err = new Error('midnight connection not established') as Error & {
        statusCode: number;
        code: string;
      };
      err.statusCode = 503;
      err.code = 'not_connected';
      throw err;
    }
    return connection;
  }

  async function ensureConnection(): Promise<ChainConnection> {
    if (connection) return connection;
    if (!connecting) {
      if (
        config.contractAddress === undefined ||
        config.walletSeed === undefined ||
        config.adminSecret === undefined
      ) {
        const err = new Error(
          'gateway is not configured for live interaction: DISPUTEVAULT_CONTRACT_ADDRESS, WALLET_SEED and ADMIN_SECRET are required',
        ) as Error & { statusCode: number; code: string };
        err.statusCode = 503;
        err.code = 'not_configured';
        connecting = Promise.reject(err);
      } else {
        connecting = connectContract({
          network: config.network,
          indexerUrl: config.indexerUrl,
          indexerWsUrl: config.indexerWsUrl,
          proofServerUrl: config.proofServerUrl,
          nodeUrl: config.nodeUrl,
          nodeWsUrl: config.nodeWsUrl,
          walletSeed: config.walletSeed,
          adminSecret: config.adminSecret,
          zkAssetsDir: config.zkAssetsDir,
          contractAddress: config.contractAddress,
          privateStateDir: config.privateStateDir,
          logger,
        })
          .then((c) => {
            connection = c;
            return c;
          })
          .catch((e) => {
            connecting = undefined;
            throw e;
          });
      }
    }
    return connecting;
  }

  // --- routes --------------------------------------------------------------

  app.get('/health', async () => {
    let midnight: unknown;
    try {
      midnight = connectionStatus(connection);
    } catch {
      midnight = { connected: false };
    }
    return {
      status: 'ok',
      service: 'disputevault-gateway',
      midnight,
      config: publicConfigView(config),
    };
  });

  app.get('/disputes', async (_req, reply) => {
    try {
      const conn = await ensureConnection();
      const [metadata, disputes] = await Promise.all([
        fetchChainMetadata(conn),
        listDisputes(conn),
      ]);
      return { ...metadata, disputes };
    } catch (e) {
      return sendError(reply, e);
    }
  });

  app.get('/disputes/:id', async (req, reply) => {
    const id = parseDisputeId((req.params as { id: string }).id);
    if (id === null) {
      const err = new Error('dispute id must be a decimal integer in 0..2^64-1') as Error & {
        statusCode: number;
        code: string;
      };
      err.statusCode = 400;
      err.code = 'invalid_dispute_id';
      return sendError(reply, err);
    }
    try {
      const conn = await ensureConnection();
      const dispute = await fetchDispute(conn, id);
      if (dispute === null) {
        const err = new Error(`dispute ${id.toString()} not found`) as Error & {
          statusCode: number;
          code: string;
        };
        err.statusCode = 404;
        err.code = 'not_found';
        return sendError(reply, err);
      }
      return dispute;
    } catch (e) {
      return sendError(reply, e);
    }
  });

  app.post('/disputes', async (req, reply) => {
    const body = req.body as
      | { evidence_wire?: unknown; envelope?: unknown }
      | undefined;
    if (body === null || typeof body !== 'object') {
      const err = new Error('body must be a JSON object') as Error & { statusCode: number; code: string };
      err.statusCode = 400;
      err.code = 'malformed_request';
      return sendError(reply, err);
    }
    const evidenceWire = parseHexBytes(body.evidence_wire, 256);
    const envelope = parseHexBytes(body.envelope, 284);
    if (evidenceWire === null || envelope === null) {
      const err = new Error(
        'evidence_wire must be 256-byte hex and envelope must be 284-byte hex',
      ) as Error & { statusCode: number; code: string };
      err.statusCode = 400;
      err.code = 'malformed_request';
      return sendError(reply, err);
    }
    try {
      const conn = await ensureConnection();
      const result = await submitDispute(conn, logger, evidenceWire, envelope);
      reply.status(201);
      return result;
    } catch (e) {
      return sendError(reply, e);
    }
  });

  app.post('/disputes/:id/verdict', async (req, reply) => {
    const id = parseDisputeId((req.params as { id: string }).id);
    if (id === null) {
      const err = new Error('dispute id must be a decimal integer in 0..2^64-1') as Error & {
        statusCode: number;
        code: string;
      };
      err.statusCode = 400;
      err.code = 'invalid_dispute_id';
      return sendError(reply, err);
    }
    const body = req.body as { verdict?: unknown } | undefined;
    if (body === null || typeof body !== 'object' || body.verdict === undefined) {
      const err = new Error('body must be {"verdict": {...VerdictV1...}}') as Error & {
        statusCode: number;
        code: string;
      };
      err.statusCode = 400;
      err.code = 'malformed_request';
      return sendError(reply, err);
    }
    // Shape-check the verdict BEFORE any chain interaction (schema errors
    // are user errors, not contract errors).
    let payload: VerdictV1;
    try {
      payload = validateVerdict(body.verdict);
    } catch (e) {
      return sendError(reply, e);
    }
    try {
      const conn = await ensureConnection();
      const result = await submitVerdict(conn, logger, id, payload);
      reply.status(201);
      return result;
    } catch (e) {
      return sendError(reply, e);
    }
  });

  app.post('/platform/register', async (req, reply) => {
    const body = req.body as { platform_public_key?: unknown } | undefined;
    const key = parseHexBytes(
      (body as { platform_public_key?: unknown } | null)?.platform_public_key,
      65,
    );
    if (key === null) {
      const err = new Error('platform_public_key must be 65-byte hex') as Error & {
        statusCode: number;
        code: string;
      };
      err.statusCode = 400;
      err.code = 'malformed_request';
      return sendError(reply, err);
    }
    try {
      const conn = await ensureConnection();
      const result = await registerPlatform(conn, logger, key);
      reply.status(201);
      return result;
    } catch (e) {
      return sendError(reply, e);
    }
  });

  /**
   * Commitment/status verification (PROTOCOL.md §10). The caller supplies a
   * canonical evidence or verdict JSON payload; the gateway canonicalizes
   * via the SDK, builds the DV1E/DV1V wire, hashes it, and compares against
   * the on-chain commitment. Public, key-free, stateless.
   */
  app.post('/verify/commitment', async (req, reply) => {
    const body = req.body as
      | { dispute_id?: unknown; kind?: unknown; payload?: unknown }
      | undefined;
    if (body === null || typeof body !== 'object') {
      const err = new Error('body must be a JSON object') as Error & { statusCode: number; code: string };
      err.statusCode = 400;
      err.code = 'malformed_request';
      return sendError(reply, err);
    }
    const id = parseDisputeId(String(body.dispute_id ?? ''));
    if (id === null || (body.kind !== 'evidence' && body.kind !== 'verdict')) {
      const err = new Error('dispute_id (decimal) and kind ("evidence"|"verdict") are required') as Error & {
        statusCode: number;
        code: string;
      };
      err.statusCode = 400;
      err.code = 'malformed_request';
      return sendError(reply, err);
    }
    if (body.kind === 'verdict' && typeof body.payload === 'object' && body.payload !== null) {
      // Enforce the §7 binding rule on the verification path too.
      try {
        const embedded = validateVerdict(body.payload).dispute_id;
        if (embedded !== id) {
          const err = new Error(
            `verdict/dispute binding mismatch (PROTOCOL §7): payload dispute_id=${embedded} does not match target dispute_id=${id}`,
          ) as Error & { statusCode: number; code: string };
          err.statusCode = 400;
          err.code = 'binding_mismatch';
          return sendError(reply, err);
        }
      } catch (e) {
        return sendError(reply, e);
      }
    }
    try {
      const conn = await ensureConnection();
      const dispute = await fetchDispute(conn, id);
      if (dispute === null) {
        const err = new Error(`dispute ${String(id)} not found`) as Error & {
          statusCode: number;
          code: string;
        };
        err.statusCode = 404;
        err.code = 'not_found';
        return sendError(reply, err);
      }
      const { canonicalizeEvidence, canonicalizeVerdict, makeEvidenceWire, makeVerdictWire } =
        await import('@disputevault/sdk');
      const canonicalJson =
        body.kind === 'evidence'
          ? canonicalizeEvidence(body.payload)
          : canonicalizeVerdict(body.payload);
      const wire =
        body.kind === 'evidence' ? makeEvidenceWire(canonicalJson) : makeVerdictWire(canonicalJson);
      const computed =
        body.kind === 'evidence'
          ? Buffer.from(await evidenceCommitment(wire)).toString('hex')
          : Buffer.from(await verdictCommitment(wire)).toString('hex');
      const onChain =
        body.kind === 'evidence' ? dispute.evidenceCommitment : dispute.verdictCommitment;
      return {
        disputeId: dispute.disputeId,
        kind: body.kind,
        matches: computed === onChain,
        computedCommitment: computed,
        onChainCommitment: onChain,
        status: dispute.status,
      };
    } catch (e) {
      return sendError(reply, e);
    }
  });

  // --- lifecycle -----------------------------------------------------------

  const ready = async (): Promise<void> => {
    await app.ready();
  };
  const close = async () => {
    if (connection) {
      try {
        await connection.close();
      } catch {
        // shutdown must not throw
      }
    }
    await app.close();
  };

  return { app, ready, close, requireConnection };
}

/** Entry point (node --experimental-strip-types src/server.ts). */
export async function main(): Promise<void> {
  const config = loadConfig();
  const logger = (await import('pino')).default({ level: process.env.LOG_LEVEL ?? 'info' });
  const server = await buildServer({ config, logger });
  try {
    await server.ready();
    await server.app.listen({ port: config.port, host: config.host });
  } catch (e) {
    logger.error({ err: e }, 'gateway failed to start');
    process.exitCode = 1;
    await server.close();
  }
}

if (process.argv[1] !== undefined && import.meta.url === `file://${process.argv[1]}`) {
  void main();
}

export type { FastifyRequest };
