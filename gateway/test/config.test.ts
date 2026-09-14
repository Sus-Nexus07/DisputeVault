/**
 * Unit tests for gateway/src/config.ts (env loading, fail-fast validation,
 * and the HTTP-safe public view that must never leak secrets).
 */
import { describe, expect, it } from 'vitest';

import { ConfigError, loadConfig, publicConfigView, type GatewayConfig } from '../src/config.js';

const HEX32 = 'aa'.repeat(32); // 64 hex chars; vector-style value, not a real key
const HEX_SEED = 'bb'.repeat(64); // 128 hex chars; vector-style value

describe('loadConfig', () => {
  it('applies the documented defaults', () => {
    const cfg = loadConfig({});
    expect(cfg.port).toBe(8787);
    expect(cfg.host).toBe('127.0.0.1');
    expect(cfg.network).toBe('undeployed');
    expect(cfg.nodeUrl).toBe('http://localhost:9944');
    expect(cfg.indexerUrl).toBe('http://localhost:8088/api/v1/graphql');
    expect(cfg.proofServerUrl).toBe('http://localhost:6300');
    expect(cfg.adminSecret).toBeUndefined();
    expect(cfg.walletSeed).toBeUndefined();
    expect(cfg.contractAddress).toBeUndefined();
  });

  it('derives websocket URLs from the http endpoints', () => {
    const cfg = loadConfig({
      MIDNIGHT_NODE_URL: 'http://node.example:9944',
      MIDNIGHT_INDEXER_URL: 'https://idx.example/api/v1/graphql',
    });
    expect(cfg.nodeWsUrl).toBe('ws://node.example:9944');
    expect(cfg.indexerWsUrl).toBe('wss://idx.example/api/v1/graphql/ws');
  });

  it('loads secrets into memory as raw bytes without echoing them', () => {
    const cfg = loadConfig({
      ADMIN_SECRET: HEX32,
      WALLET_SEED: HEX_SEED,
      DISPUTEVAULT_CONTRACT_ADDRESS: 'cc'.repeat(32),
    });
    expect(cfg.adminSecret).toEqual(Uint8Array.from(Buffer.from(HEX32, 'hex')));
    expect(cfg.walletSeed).toBe(HEX_SEED);
    expect(cfg.contractAddress).toBe(`0x${'cc'.repeat(32)}`);
  });

  it('rejects a malformed ADMIN_SECRET before the process can mis-wire proofs', () => {
    expect(() => loadConfig({ ADMIN_SECRET: 'deadbeef' })).toThrow(ConfigError);
    expect(() => loadConfig({ ADMIN_SECRET: 'zz'.repeat(32) })).toThrow(ConfigError);
  });

  it('rejects an unknown MIDNIGHT_NETWORK', () => {
    expect(() => loadConfig({ MIDNIGHT_NETWORK: 'mainnet' })).toThrow(ConfigError);
  });

  it('rejects a non-integer or out-of-range GATEWAY_PORT', () => {
    expect(() => loadConfig({ GATEWAY_PORT: '0' })).toThrow(ConfigError);
    expect(() => loadConfig({ GATEWAY_PORT: '70000' })).toThrow(ConfigError);
    expect(() => loadConfig({ GATEWAY_PORT: 'not-a-port' })).toThrow(ConfigError);
    expect(loadConfig({ GATEWAY_PORT: '9000' }).port).toBe(9000);
  });

  it('rejects non-http service URLs and non-ws websocket URLs', () => {
    expect(() => loadConfig({ MIDNIGHT_NODE_URL: 'ftp://x' })).toThrow(ConfigError);
    expect(() => loadConfig({ MIDNIGHT_INDEXER_URL: 'nope' })).toThrow(ConfigError);
    expect(() => loadConfig({ MIDNIGHT_PROOF_SERVER_URL: 'ws://should-be-http' })).toThrow(ConfigError);
    expect(() => loadConfig({ MIDNIGHT_NODE_WS_URL: 'http://should-be-ws' })).toThrow(ConfigError);
  });
});

describe('publicConfigView', () => {
  it('exposes only non-sensitive settings (endpoints, booleans)', () => {
    const cfg: GatewayConfig = loadConfig({
      ADMIN_SECRET: HEX32,
      WALLET_SEED: HEX_SEED,
      DISPUTEVAULT_CONTRACT_ADDRESS: 'cc'.repeat(32),
    });
    const view = JSON.stringify(publicConfigView(cfg));
    const parsed = JSON.parse(view) as Record<string, unknown>;

    expect(parsed['network']).toBe('undeployed');
    expect(parsed['adminSecretConfigured']).toBe(true);
    expect(parsed['walletSeedConfigured']).toBe(true);
    expect(parsed['contractAddress']).toBe(`0x${'cc'.repeat(32)}`);

    // NO secret material in the view, at any nesting level: neither the raw
    // secret values nor any secret-shaped field (only *Configured booleans
    // exist). The contract ADDRESS is public and may appear; secrets may not.
    expect(view).not.toContain(HEX_SEED);
    expect(view).not.toContain(HEX32);
    expect(Object.keys(parsed).some((k) => !k.endsWith('Configured') && /secret|seed|admin/i.test(k))).toBe(false);
  });

  it('reports configured=false booleans when secrets are absent', () => {
    const parsed = publicConfigView(loadConfig({}));
    expect(parsed['adminSecretConfigured']).toBe(false);
    expect(parsed['walletSeedConfigured']).toBe(false);
  });
});
