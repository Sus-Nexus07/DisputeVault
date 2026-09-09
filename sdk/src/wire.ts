/**
 * DisputeVault wire format (PROTOCOL.md §3).
 *
 *   offset  size  field
 *   0       4     magic          ASCII "DV1E" (evidence) | "DV1V" (verdict)
 *   4       2     json_len       uint16 big-endian
 *   6       n     json           canonical JSON (n == json_len)
 *   6+n     ...   padding        0x00 up to the fixed wire size
 *
 * Rules enforced here:
 *   - json_len == actual JSON byte count; 6 + json_len <= wire size
 *   - padding bytes MUST be zero
 *   - magic doubles as domain separation (DV1E vs DV1V never interchangeable)
 *   - a wire that violates any rule is rejected, never repaired
 */
import { ProtocolError, byteLength } from './canonical.js';
import { WIRE } from './schema.js';

export const EVIDENCE_MAGIC = 'DV1E';
export const VERDICT_MAGIC = 'DV1V';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export type WireKind = 'evidence' | 'verdict';

const WIRE_SIZE: Record<WireKind, number> = {
  evidence: WIRE.evidenceWireSize,
  verdict: WIRE.verdictWireSize,
};

const MAX_JSON: Record<WireKind, number> = {
  evidence: WIRE.evidenceMaxJsonBytes,
  verdict: WIRE.verdictMaxJsonBytes,
};

const MAGIC: Record<WireKind, string> = {
  evidence: EVIDENCE_MAGIC,
  verdict: VERDICT_MAGIC,
};

/** Frame a canonical JSON string into a fixed-size DV1E/DV1V wire. */
export function makeWire(kind: WireKind, canonicalJson: string): Uint8Array {
  const jsonBytes = encoder.encode(canonicalJson);
  const wireSize = WIRE_SIZE[kind];
  const maxJson = MAX_JSON[kind];
  if (jsonBytes.length > maxJson) {
    throw new ProtocolError(
      `canonical JSON is ${jsonBytes.length} bytes; ${kind} budget is ${maxJson} (PROTOCOL §3) - rejected, never truncated`,
    );
  }
  const wire = new Uint8Array(wireSize);
  wire.set(encoder.encode(MAGIC[kind]), 0);
  wire[4] = (jsonBytes.length >> 8) & 0xff;
  wire[5] = jsonBytes.length & 0xff;
  wire.set(jsonBytes, 6);
  return wire;
}

export const makeEvidenceWire = (canonicalJson: string): Uint8Array =>
  makeWire('evidence', canonicalJson);
export const makeVerdictWire = (canonicalJson: string): Uint8Array =>
  makeWire('verdict', canonicalJson);

/** Parsed view of a wire. */
export interface ParsedWire {
  kind: WireKind;
  magic: string;
  json: string;
  jsonBytes: Uint8Array;
  jsonLen: number;
  wire: Uint8Array;
}

/**
 * Strictly parse a wire of the expected kind. Any deviation - wrong magic,
 * inconsistent length field, non-zero padding, invalid UTF-8, oversized JSON
 * - throws ProtocolError. Verifiers MUST use this before re-hashing.
 */
export function parseWire(kind: WireKind, wire: Uint8Array): ParsedWire {
  const wireSize = WIRE_SIZE[kind];
  if (wire.length !== wireSize) {
    throw new ProtocolError(
      `${kind} wire must be exactly ${wireSize} bytes, got ${wire.length}`,
    );
  }
  const magic = decoder.decode(wire.subarray(0, 4));
  if (magic !== MAGIC[kind]) {
    throw new ProtocolError(
      `${kind} wire magic must be "${MAGIC[kind]}", got "${magic}"`,
    );
  }
  const jsonLen = (wire[4]! << 8) | wire[5]!;
  if (6 + jsonLen > wireSize) {
    throw new ProtocolError(
      `${kind} wire json_len ${jsonLen} exceeds wire capacity (${wireSize} bytes)`,
    );
  }
  if (jsonLen > MAX_JSON[kind]) {
    throw new ProtocolError(
      `${kind} wire json_len ${jsonLen} exceeds the ${MAX_JSON[kind]}-byte budget (PROTOCOL §3)`,
    );
  }
  const jsonBytes = wire.slice(6, 6 + jsonLen);
  const json = decoder.decode(jsonBytes); // fatal: throws on invalid UTF-8
  // json_len must equal the actual JSON byte count; a too-large length field
  // swallows padding bytes into the JSON, which cannot parse as JSON.
  try {
    JSON.parse(json);
  } catch {
    throw new ProtocolError(
      `${kind} wire json_len ${jsonLen} is inconsistent with the embedded JSON (PROTOCOL §3)`,
    );
  }
  for (let i = 6 + jsonLen; i < wireSize; i++) {
    if (wire[i] !== 0) {
      throw new ProtocolError(
        `${kind} wire has non-zero padding at offset ${i} (PROTOCOL §3)`,
      );
    }
  }
  return { kind, magic, json, jsonBytes, jsonLen, wire: wire.slice() };
}
