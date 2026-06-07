import { gcm } from '@noble/ciphers/aes.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha512 } from '@noble/hashes/sha2.js';

import { concatBytes, toBytes, utf8ToBytes } from './encoding.js';
import type { Bytes } from './types.js';

const KEY_BYTES = 32;
const NONCE_BYTES = 12;
const DERIVED_BYTES = KEY_BYTES + NONCE_BYTES;

export function deriveAesMaterial(sharedSecret: Bytes, challenge: string, kemId: string): { key: Bytes; nonce: Bytes } {
  const salt = utf8ToBytes(`PQSeal v1 challenge:${challenge}`);
  const info = utf8ToBytes(`PQSeal v1 AES-256-GCM HKDF-SHA512 kem:${kemId}`);
  const okm = hkdf(sha512, sharedSecret, salt, info, DERIVED_BYTES);
  return {
    key: okm.slice(0, KEY_BYTES),
    nonce: okm.slice(KEY_BYTES)
  };
}

export function encryptAesGcm(key: Bytes, nonce: Bytes, plaintext: Bytes, aad?: Bytes | string): Bytes {
  return gcm(key, nonce, aad === undefined ? undefined : toBytes(aad)).encrypt(plaintext);
}

export function decryptAesGcm(key: Bytes, nonce: Bytes, data: Bytes, aad?: Bytes | string): Bytes {
  return gcm(key, nonce, aad === undefined ? undefined : toBytes(aad)).decrypt(data);
}

export function jsonToBytes(value: unknown): Bytes {
  return utf8ToBytes(JSON.stringify(value));
}

export function makeFieldAad(keys: readonly PropertyKey[]): Bytes {
  return concatBytes(utf8ToBytes('PQSeal v1 fields:'), utf8ToBytes(JSON.stringify([...keys].map(String).sort())));
}
