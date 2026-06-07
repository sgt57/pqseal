# PQSeal Protocol

PQSeal uses a server-issued one-time challenge to bind ML-KEM key agreement to one AES-GCM encryption.

## Flow

1. The server keeps a current in-memory KEM keypair and rotates it periodically.
2. The server issues `{ v, kem, publicKey, challenge, expiresAt }`.
3. The client encapsulates to `publicKey`, producing `sharedSecret` and KEM `ciphertext`.
4. The client derives 44 bytes with HKDF-SHA512:
   - IKM: KEM shared secret
   - salt: `PQSeal v1 challenge:${challenge}`
   - info: `PQSeal v1 AES-256-GCM HKDF-SHA512 kem:${kem}`
5. The first 32 bytes are the AES-256-GCM key; the next 12 bytes are the AES-GCM nonce.
6. The client sends `{ v, kem, challenge, ciphertext, data }`.
7. The server atomically consumes the challenge, decapsulates, derives the same key material, and decrypts.

## Envelope

```ts
interface PQSealEnvelope {
  v: 1;
  kem: string;
  challenge: string;
  ciphertext: string;
  data: string;
}
```

All binary values are base64url encoded without padding.

## Replay Protection

Challenges are one-time use. `open()` deletes the challenge before decapsulation and decryption, so replayed envelopes fail even if the first decryption attempt was malformed.

Expired challenges are rejected. The in-memory challenge map is cleaned opportunistically during issue/open calls, and `cleanup()` is available for explicit idle cleanup.

## Key Rotation

The active KEM keypair rotates every `keyRotationMs`. Existing unexpired challenges keep a reference to the keypair that issued them, so rotation does not invalidate live challenges.

## HNDL Scope

PQSeal protects sealed payload contents from future TLS decryption, provided the attacker did not also compromise the server process memory, challenge store, private KEM key material, or endpoint logic at request time.
