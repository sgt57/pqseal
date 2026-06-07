import { randomBytes } from '@noble/hashes/utils.js';

import { decryptAesGcm, deriveAesMaterial, encryptAesGcm, jsonToBytes, makeFieldAad } from './crypto.js';
import { base64UrlDecode, base64UrlEncode, bytesToUtf8, toBytes } from './encoding.js';
import { PQSealError } from './errors.js';
import { mlKem768 } from './kem.js';
import type {
  Bytes,
  ChallengeBundle,
  FieldSealedObject,
  KemAdapter,
  KemKeyPair,
  OpenOptions,
  PQSealClient,
  PQSealClientOptions,
  PQSealEnvelope,
  PQSealServer,
  PQSealServerOptions,
  SealOptions
} from './types.js';

const VERSION = 1;
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
  return base64UrlEncode(randomBytes(16));
}

function assertPositiveInteger(name: string, value: number): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new PQSealError('BAD_OPTIONS', `${name} must be a positive safe integer`);
  }
}

function assertKeyRotationMs(value: number): void {
  assertPositiveInteger('keyRotationMs', value);
  if (value < MIN_KEY_ROTATION_MS || value > MAX_KEY_ROTATION_MS) {
    throw new PQSealError('BAD_OPTIONS', 'keyRotationMs must be between 1 minute and 24 hours');
  }
}

function assertEnvelope(envelope: PQSealEnvelope): void {
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

function assertBundle(bundle: ChallengeBundle): void {
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

function parseJson<T>(bytes: Bytes): T {
  return JSON.parse(bytesToUtf8(bytes)) as T;
}

function normalizeKems(kems?: Iterable<KemAdapter>): Map<string, KemAdapter> {
  const map = new Map<string, KemAdapter>();
  for (const kem of kems ?? [mlKem768]) {
    if (!kem.id || map.has(kem.id)) {
      throw new PQSealError('BAD_KEM', `Invalid or duplicate KEM id: ${kem.id}`);
    }
    map.set(kem.id, kem);
  }
  return map;
}

export function createPQSealClient(options: PQSealClientOptions = {}): PQSealClient {
  const knownKems = normalizeKems(options.kems);

  function getKem(kemId: string): KemAdapter {
    const kem = knownKems.get(kemId);
    if (!kem) {
      throw new PQSealError('BAD_KEM', `Unsupported KEM: ${kemId}`);
    }
    return kem;
  }

  function seal(bundle: ChallengeBundle, plaintext: Bytes | string, options: SealOptions = {}): PQSealEnvelope {
    assertBundle(bundle);
    const kem = getKem(bundle.kem);
    const { ciphertext, sharedSecret } = kem.encapsulate(base64UrlDecode(bundle.publicKey));
    const { key, nonce } = deriveAesMaterial(sharedSecret, bundle.challenge, kem.id);
    const data = encryptAesGcm(key, nonce, toBytes(plaintext), options.aad);
    return {
      v: VERSION,
      kem: kem.id,
      challenge: bundle.challenge,
      ciphertext: base64UrlEncode(ciphertext),
      data: base64UrlEncode(data)
    };
  }

  return {
    seal,
    sealJson(bundle, value, options) {
      return seal(bundle, jsonToBytes(value), options);
    },
    sealFields(bundle, object, keys, options) {
      const sealedFields: Record<string, unknown> = {};
      const visible: Record<string, unknown> = { ...object };
      for (const key of keys) {
        const stringKey = String(key);
        sealedFields[stringKey] = object[key];
        delete visible[stringKey];
      }
      return {
        ...visible,
        __pqsealFields: keys.map(String),
        __pqseal: seal(bundle, jsonToBytes(sealedFields), {
          ...options,
          aad: options?.aad ?? makeFieldAad(keys)
        })
      } as Omit<typeof object, (typeof keys)[number]> & FieldSealedObject;
    }
  };
}

export function createPQSealServer(options: PQSealServerOptions = {}): PQSealServer {
  const kem = options.kem ?? mlKem768;
  const challengeTtlMs = options.challengeTtlMs ?? DEFAULT_CHALLENGE_TTL_MS;
  const keyRotationMs = options.keyRotationMs ?? DEFAULT_KEY_ROTATION_MS;
  const now = options.now ?? Date.now;
  const challengeGenerator = options.challengeGenerator ?? defaultChallengeGenerator;
  const challenges = new Map<string, ChallengeRecord>();
  let currentKey: KeyState | undefined;

  assertPositiveInteger('challengeTtlMs', challengeTtlMs);
  assertKeyRotationMs(keyRotationMs);

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

  function cleanup(): number {
    const timestamp = now();
    let deleted = 0;
    for (const [challenge, record] of challenges) {
      if (record.expiresAt > timestamp) {
        break;
      }
      challenges.delete(challenge);
      deleted += 1;
    }
    return deleted;
  }

  let timer: ReturnType<typeof setInterval> | undefined;
  if (options.autoCleanup) {
    const cleanupIntervalMs = options.cleanupIntervalMs ?? challengeTtlMs;
    assertPositiveInteger('cleanupIntervalMs', cleanupIntervalMs);
    timer = setInterval(cleanup, cleanupIntervalMs);
    (timer as { unref?: () => void }).unref?.();
  }

  function issueChallenge(): ChallengeBundle {
    const timestamp = now();
    cleanup();
    const key = rotateIfNeeded(timestamp);
    const expiresAt = timestamp + challengeTtlMs;
    let challenge = '';
    for (let attempt = 0; attempt < MAX_CHALLENGE_GENERATION_ATTEMPTS; attempt += 1) {
      challenge = challengeGenerator();
      const existing = challenges.get(challenge);
      if (!existing || existing.expiresAt <= timestamp) {
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
