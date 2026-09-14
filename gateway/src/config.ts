/**
 * DisputeVault gateway configuration (environment variables).
 *
 * Follows the existing `.env.example` conventions. Secrets are read into
 * memory for transaction construction ONLY; they are never logged, never
 * echoed in HTTP responses, and never written to disk by this module.
 *
 * Midnight endpoints follow `.env.example`:
 *   MIDNIGHT_NETWORK           undeployed (local devnet) | preview | preprod
 *   MIDNIGHT_NODE_URL          local devnet:  http://localhost:9944
 *   MIDNIGHT_INDEXER_URL       local devnet:  http://localhost:8088/api/v1/graphql
 *   MIDNIGHT_PROOF_SERVER_URL  local devnet:  http://localhost:6300
 *   GATEWAY_URL                this service's public endpoint (advertising only)
 *
 * Secrets (SECURITY.md §8):
 *   ADMIN_SECRET               Bytes<32> hex; bound to admin_authority at
 *                              deployment; used as the adminSecret() witness
 *                              for register_platform / post_verdict proofs.
 *   WALLET_SEED                BIP32 mnemonic seed (hex) for the gateway's
 *                              balancing wallet. Optional in Wave 1 (reads
 *                              work without it); required for submits.
 *
 * The platform evidence-encryption private key intentionally has NO gateway
 * variable: only the Go worker holds it (docs/SECURITY.md §8), and the
 * gateway never receives plaintext evidence.
 */

/** Networks accepted in MIDNIGHT_NETWORK. */
export const MIDNIGHT_NETWORKS = ['undeployed', 'preview', 'preprod'] as const;
export type MidnightNetwork = (typeof MIDNIGHT_NETWORKS)[number];

export interface GatewayConfig {
  /** HTTP bind port. */
  readonly port: number;
  /** HTTP bind host. */
  readonly host: string;
  /** Midnight network identifier (midnight-js-network-id value). */
  readonly network: MidnightNetwork;
  /** Midnight node (Substrate) RPC URL. */
  readonly nodeUrl: string;
  /** Midnight indexer GraphQL query URL. */
  readonly indexerUrl: string;
  /** Midnight indexer GraphQL websocket subscription URL. */
  readonly indexerWsUrl: string;
  /** Midnight node websocket URL (wallet relay). */
  readonly nodeWsUrl: string;
  /** Midnight proof-server URL. */
  readonly proofServerUrl: string;
  /**
   * Admin secret as raw 32 bytes (from ADMIN_SECRET hex). Empty when unset —
   * read endpoints stay available; admin-authorized submits fail closed.
   */
  readonly adminSecret: Uint8Array | undefined;
  /** BIP32 wallet seed (hex) for the balancing wallet; optional for reads. */
  readonly walletSeed: string | undefined;
  /** Directory holding compiled ZK artifacts (zkir/, keys/ subdirs). */
  readonly zkAssetsDir: string;
  /** Address of the deployed DisputeVault contract (0x-prefixed 32-byte hex). */
  readonly contractAddress: string | undefined;
  /** Directory for gateway-local state (private-state LevelDB store). */
  readonly privateStateDir: string;
}

const DEFAULTS = {
  port: 8787,
  host: '127.0.0.1',
  network: 'undeployed' as MidnightNetwork,
  nodeUrl: 'http://localhost:9944',
  indexerUrl: 'http://localhost:8088/api/v1/graphql',
  indexerWsUrl: 'ws://localhost:8088/api/v1/graphql/ws',
  proofServerUrl: 'http://localhost:6300',
  nodeWsUrl: 'ws://localhost:9944',
  zkAssetsDir: '../contract/src/managed/disputevault',
  privateStateDir: './.gateway-state',
};

/** True when the value is a non-empty string after trimming. */
const isSet = (v: string | undefined): v is string => typeof v === 'string' && v.trim().length > 0;

/** Parse ADMIN_SECRET hex into exactly 32 bytes, or undefined when unset. */
function parseAdminSecret(raw: string | undefined): Uint8Array | undefined {
  if (!isSet(raw)) return undefined;
  const hex = raw.trim().toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new ConfigError('ADMIN_SECRET must be exactly 64 hex characters (32 bytes)');
  }
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

/** Validate a hex contract address (32 bytes); returns undefined when unset. */
function parseContractAddress(raw: string | undefined): string | undefined {
  if (!isSet(raw)) return undefined;
  const hex = raw.trim().toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new ConfigError(
      'DISPUTEVAULT_CONTRACT_ADDRESS must be 64 hex characters (32 bytes)',
    );
  }
  return `0x${hex}`;
}

/** Derive the ws(s) URL from an http(s) URL (adds no path). */
function httpToWs(httpUrl: string): string {
  if (httpUrl.startsWith('https://')) return `wss://${httpUrl.slice('https://'.length)}`;
  if (httpUrl.startsWith('http://')) return `ws://${httpUrl.slice('http://'.length)}`;
  return DEFAULTS.nodeWsUrl;
}

/** Pick the websocket indexer URL, deriving one when only HTTP was given. */
function indexerWsUrl(raw: string | undefined, httpUrl: string): string {
  if (isSet(raw)) return raw.trim();
  if (httpUrl.startsWith('https://')) return `wss://${httpUrl.slice('https://'.length)}/ws`;
  if (httpUrl.startsWith('http://')) return `ws://${httpUrl.slice('http://'.length)}/ws`;
  return DEFAULTS.indexerWsUrl;
}

/** Error thrown when the environment cannot produce a usable configuration. */
export class ConfigError extends Error {
  constructor(message: string) {
    super(`disputevault-gateway config: ${message}`);
    this.name = 'ConfigError';
  }
}

/**
 * Load configuration from the environment (process.env or an explicit
 * override, used by tests). Throws ConfigError on malformed values so the
 * process fails fast instead of mis-wiring the Midnight boundary.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): GatewayConfig {
  const network = isSet(env.MIDNIGHT_NETWORK) ? (env.MIDNIGHT_NETWORK.trim() as MidnightNetwork) : DEFAULTS.network;
  if (!MIDNIGHT_NETWORKS.includes(network)) {
    throw new ConfigError(
      `MIDNIGHT_NETWORK must be one of ${MIDNIGHT_NETWORKS.join(' | ')}, got "${env.MIDNIGHT_NETWORK}"`,
    );
  }

  const portRaw = env.GATEWAY_PORT;
  let port = DEFAULTS.port;
  if (isSet(portRaw)) {
    port = Number(portRaw);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new ConfigError(`GATEWAY_PORT must be an integer in 1..65535, got "${portRaw}"`);
    }
  }

  const indexerUrl = isSet(env.MIDNIGHT_INDEXER_URL) ? env.MIDNIGHT_INDEXER_URL.trim() : DEFAULTS.indexerUrl;
  const nodeUrl = isSet(env.MIDNIGHT_NODE_URL) ? env.MIDNIGHT_NODE_URL.trim() : DEFAULTS.nodeUrl;
  const nodeWsUrl = isSet(env.MIDNIGHT_NODE_WS_URL)
    ? env.MIDNIGHT_NODE_WS_URL.trim()
    : httpToWs(nodeUrl);
  const proofServerUrl = isSet(env.MIDNIGHT_PROOF_SERVER_URL)
    ? env.MIDNIGHT_PROOF_SERVER_URL.trim()
    : DEFAULTS.proofServerUrl;

  for (const [name, url] of [
    ['MIDNIGHT_NODE_URL', nodeUrl],
    ['MIDNIGHT_INDEXER_URL', indexerUrl],
    ['MIDNIGHT_PROOF_SERVER_URL', proofServerUrl],
  ] as const) {
    if (!/^https?:\/\//.test(url)) {
      throw new ConfigError(`${name} must be an http(s) URL, got "${url}"`);
    }
  }
  for (const [name, url] of [
    ['MIDNIGHT_NODE_WS_URL', nodeWsUrl],
  ] as const) {
    if (!/^wss?:\/\//.test(url)) {
      throw new ConfigError(`${name} must be a ws(s) URL, got "${url}"`);
    }
  }

  return {
    port,
    host: isSet(env.GATEWAY_HOST) ? env.GATEWAY_HOST.trim() : DEFAULTS.host,
    network,
    nodeUrl,
    nodeWsUrl,
    indexerUrl,
    indexerWsUrl: indexerWsUrl(env.MIDNIGHT_INDEXER_WS_URL, indexerUrl),
    proofServerUrl,
    privateStateDir: isSet(env.GATEWAY_STATE_DIR) ? env.GATEWAY_STATE_DIR.trim() : DEFAULTS.privateStateDir,
    adminSecret: parseAdminSecret(env.ADMIN_SECRET),
    walletSeed: isSet(env.WALLET_SEED) ? env.WALLET_SEED.trim() : undefined,
    zkAssetsDir: isSet(env.DISPUTEVAULT_ZK_ASSETS_DIR)
      ? env.DISPUTEVAULT_ZK_ASSETS_DIR.trim()
      : DEFAULTS.zkAssetsDir,
    contractAddress: parseContractAddress(env.DISPUTEVAULT_CONTRACT_ADDRESS),
  };
}

/**
 * Redacted, HTTP-safe view of the configuration. Never includes secrets;
 * only endpoint URLs and non-sensitive settings are exposed.
 */
export function publicConfigView(config: GatewayConfig): Record<string, unknown> {
  return {
    network: config.network,
    nodeUrl: config.nodeUrl,
    indexerUrl: config.indexerUrl,
    proofServerUrl: config.proofServerUrl,
    contractAddress: config.contractAddress ?? null,
    adminSecretConfigured: config.adminSecret !== undefined,
    walletSeedConfigured: config.walletSeed !== undefined,
  };
}
