import { gcm } from '@noble/ciphers/aes.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha512 } from '@noble/hashes/sha2.js';

import type { Bytes } from './types.js';

interface CryptoEncoding {
  concatBytes(...parts: Uint8Array[]): Uint8Array;
  toBytes(value: Uint8Array | string): Uint8Array;
  utf8ToBytes(value: string): Uint8Array;
}

const KEY_BYTES = 32;
const NONCE_BYTES = 12;
const DERIVED_BYTES = KEY_BYTES + NONCE_BYTES;

export function createCrypto(encoding: CryptoEncoding): {
  deriveAesMaterial(sharedSecret: Bytes, challenge: string, kemId: string): { key: Bytes; nonce: Bytes };
  encryptAesGcm(key: Bytes, nonce: Bytes, plaintext: Bytes, aad?: Bytes | string): Bytes;
  decryptAesGcm(key: Bytes, nonce: Bytes, data: Bytes, aad?: Bytes | string): Bytes;
  jsonToBytes(value: unknown): Bytes;
  makeFieldAad(keys: readonly PropertyKey[]): Bytes;
} {
  return {
    deriveAesMaterial(sharedSecret, challenge, kemId) {
      const salt = encoding.utf8ToBytes(`PQSeal v1 challenge:${challenge}`);
      const info = encoding.utf8ToBytes(`PQSeal v1 AES-256-GCM HKDF-SHA512 kem:${kemId}`);
      const okm = hkdf(sha512, sharedSecret, salt, info, DERIVED_BYTES);
      return {
        key: okm.slice(0, KEY_BYTES),
        nonce: okm.slice(KEY_BYTES)
      };
    },
    encryptAesGcm(key, nonce, plaintext, aad) {
      return gcm(key, nonce, aad === undefined ? undefined : encoding.toBytes(aad)).encrypt(plaintext);
    },
    decryptAesGcm(key, nonce, data, aad) {
      return gcm(key, nonce, aad === undefined ? undefined : encoding.toBytes(aad)).decrypt(data);
    },
    jsonToBytes(value) {
      return encoding.utf8ToBytes(JSON.stringify(value));
    },
    makeFieldAad(keys) {
      return encoding.concatBytes(
        encoding.utf8ToBytes('PQSeal v1 fields:'),
        encoding.utf8ToBytes(JSON.stringify([...keys].map(String).sort()))
      );
    }
  };
}
