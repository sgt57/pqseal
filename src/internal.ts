import { bytesToUtf8 } from './encoding.js';
import { PQSealError } from './errors.js';
import { mlKem768 } from './kem.js';
import type { Bytes, ChallengeBundle, KemAdapter, PQSealEnvelope } from './types.js';

export const VERSION = 1;

export function assertPositiveInteger(name: string, value: number): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new PQSealError('BAD_OPTIONS', `${name} must be a positive safe integer`);
  }
}

export function assertEnvelope(envelope: PQSealEnvelope): void {
  if (
    envelope === null ||
    typeof envelope !== 'object' ||
    envelope.v !== VERSION ||
    typeof envelope.kem !== 'string' ||
    typeof envelope.challenge !== 'string' ||
    typeof envelope.ciphertext !== 'string' ||
    typeof envelope.data !== 'string'
  ) {
    throw new PQSealError('BAD_ENVELOPE', 'Malformed PQSeal envelope');
  }
}

export function assertBundle(bundle: ChallengeBundle): void {
  if (
    bundle === null ||
    typeof bundle !== 'object' ||
    bundle.v !== VERSION ||
    typeof bundle.kem !== 'string' ||
    typeof bundle.publicKey !== 'string' ||
    typeof bundle.challenge !== 'string' ||
    !Number.isSafeInteger(bundle.expiresAt)
  ) {
    throw new PQSealError('BAD_BUNDLE', 'Malformed PQSeal challenge bundle');
  }
}

export function parseJson<T>(bytes: Bytes): T {
  return JSON.parse(bytesToUtf8(bytes)) as T;
}

export function normalizeKems(kems?: Iterable<KemAdapter>): Map<string, KemAdapter> {
  const map = new Map<string, KemAdapter>();
  for (const kem of kems ?? [mlKem768]) {
    if (!kem.id || map.has(kem.id)) {
      throw new PQSealError('BAD_KEM', `Invalid or duplicate KEM id: ${kem.id}`);
    }
    map.set(kem.id, kem);
  }
  return map;
}
