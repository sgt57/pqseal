import { deriveAesMaterial, encryptAesGcm, jsonToBytes, makeFieldAad } from './crypto.js';
import { base64UrlDecode, base64UrlEncode, toBytes } from './encoding.js';
import { PQSealError } from './errors.js';
import { assertBundle, normalizeKems, VERSION } from './internal.js';
import type {
  Bytes,
  ChallengeBundle,
  FieldSealedObject,
  KemAdapter,
  PQSealClient,
  PQSealClientOptions,
  PQSealEnvelope,
  SealOptions
} from './types.js';

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
