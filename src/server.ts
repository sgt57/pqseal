import { randomBytes } from 'node:crypto';

import { decryptAesGcm, deriveAesMaterial, makeFieldAad } from './node-crypto.js';
import { base64UrlDecode, base64UrlEncode, bytesToUtf8 } from './node-encoding.js';
import { PQSealError } from './errors.js';
import { mlKem768 } from './kem.js';
import { assertEnvelope, assertPositiveInteger, VERSION } from './internal.js';
import type {
  Bytes,
  ChallengeBundle,
  FieldSealedObject,
  KemAdapter,
  KemKeyPair,
  OpenOptions,
  PQSealEnvelope,
  PQSealServer,
  PQSealServerOptions
} from './types.js';

const DEFAULT_CHALLENGE_TTL_MS = 60_000;
const DEFAULT_KEY_ROTATION_MS = 30 * 60_000;
const MIN_KEY_ROTATION_MS = 60_000;
const MAX_KEY_ROTATION_MS = 24 * 60 * 60_000;
const MAX_CHALLENGE_GENERATION_ATTEMPTS = 1024;

interface KeyState {
  keyPair: KemKeyPair;
  createdAt: number;
  expiresAt: number;
}

interface ChallengeRecord {
  kem: KemAdapter;
  keyPair: KemKeyPair;
  expiresAt: number;
}

function defaultChallengeGenerator(): string {
  return randomBytes(16).toString('base64url');
}

function parseJson<T>(bytes: Bytes): T {
  return JSON.parse(bytesToUtf8(bytes)) as T;
}

function assertKeyRotationMs(value: number): void {
  assertPositiveInteger('keyRotationMs', value);
  if (value < MIN_KEY_ROTATION_MS || value > MAX_KEY_ROTATION_MS) {
    throw new PQSealError('BAD_OPTIONS', 'keyRotationMs must be between 1 minute and 24 hours');
  }
}

export function createPQSealServer(options: PQSealServerOptions = {}): PQSealServer {
  const kem = options.kem ?? mlKem768;
  const challengeTtlMs = options.challengeTtlMs ?? DEFAULT_CHALLENGE_TTL_MS;
  const keyRotationMs = options.keyRotationMs ?? DEFAULT_KEY_ROTATION_MS;
  const cleanupInterval = options.cleanupInterval ?? challengeTtlMs;
  const now = options.now ?? Date.now;
  const challengeGenerator = options.challengeGenerator ?? defaultChallengeGenerator;
  const challenges = new Map<string, ChallengeRecord>();
  let currentKey: KeyState | undefined;

  assertPositiveInteger('challengeTtlMs', challengeTtlMs);
  assertKeyRotationMs(keyRotationMs);
  assertPositiveInteger('cleanupInterval', cleanupInterval);

  function rotateIfNeeded(timestamp: number): KeyState {
    if (!currentKey || timestamp >= currentKey.expiresAt) {
      currentKey = {
        keyPair: kem.keygen(),
        createdAt: timestamp,
        expiresAt: timestamp + keyRotationMs
      };
    }
    return currentKey;
  }

  function cleanup(): void {
    const timestamp = now();
    for (const [challenge, record] of challenges) {
      if (record.expiresAt > timestamp) {
        break;
      }
      challenges.delete(challenge);
    }
  }

  let timer: ReturnType<typeof setInterval> | undefined = setInterval(cleanup, cleanupInterval);
  (timer as { unref?: () => void }).unref?.();

  function issueChallenge(): ChallengeBundle {
    const timestamp = now();
    const key = rotateIfNeeded(timestamp);
    const expiresAt = timestamp + challengeTtlMs;
    let challenge = '';
    for (let attempt = 0; attempt < MAX_CHALLENGE_GENERATION_ATTEMPTS; ++attempt) {
      challenge = challengeGenerator();
      const existing = challenges.get(challenge);
      if (!existing) break;
      if (existing.expiresAt <= timestamp) {
        challenges.delete(challenge);
        break;
      }
      challenge = '';
    }
    if (!challenge) {
      throw new PQSealError('CHALLENGE_COLLISION', 'Unable to generate a unique challenge');
    }
    challenges.set(challenge, { kem, keyPair: key.keyPair, expiresAt });
    return {
      v: VERSION,
      kem: kem.id,
      publicKey: base64UrlEncode(key.keyPair.publicKey),
      challenge,
      expiresAt
    };
  }

  function open(envelope: PQSealEnvelope, options: OpenOptions = {}): Bytes {
    assertEnvelope(envelope);
    const timestamp = now();
    const record = challenges.get(envelope.challenge);
    if (!record) {
      cleanup();
      throw new PQSealError('CHALLENGE_REPLAYED', 'Challenge is missing or already consumed');
    }
    challenges.delete(envelope.challenge);
    if (record.expiresAt <= timestamp) {
      throw new PQSealError('CHALLENGE_EXPIRED', 'Challenge has expired');
    }
    if (envelope.kem !== record.kem.id) {
      throw new PQSealError('BAD_KEM', `Envelope KEM ${envelope.kem} does not match challenge KEM ${record.kem.id}`);
    }
    try {
      const sharedSecret = record.kem.decapsulate(base64UrlDecode(envelope.ciphertext), record.keyPair.secretKey);
      const { key, nonce } = deriveAesMaterial(sharedSecret, envelope.challenge, record.kem.id);
      return decryptAesGcm(key, nonce, base64UrlDecode(envelope.data), options.aad);
    } catch (error) {
      if (error instanceof PQSealError) {
        throw error;
      }
      throw new PQSealError('DECRYPT_FAILED', 'Unable to decrypt PQSeal envelope');
    }
  }

  return {
    issueChallenge,
    open,
    openJson(envelope, openOptions) {
      return parseJson(open(envelope, openOptions));
    },
    openFields<T extends Record<string, unknown>>(sealedObject: FieldSealedObject, openOptions?: OpenOptions) {
      if (
        !sealedObject ||
        typeof sealedObject !== 'object' ||
        !sealedObject.__pqseal ||
        !Array.isArray(sealedObject.__pqsealFields)
      ) {
        throw new PQSealError('BAD_ENVELOPE', 'Missing __pqseal field envelope');
      }
      const { __pqseal, __pqsealFields, ...visible } = sealedObject;
      const fields = parseJson<Record<string, unknown>>(
        open(__pqseal, {
          ...openOptions,
          aad: openOptions?.aad ?? makeFieldAad(__pqsealFields)
        })
      );
      return { ...visible, ...fields } as T;
    },
    cleanup,
    close() {
      if (timer) {
        clearInterval(timer);
        timer = undefined;
      }
    }
  };
}
