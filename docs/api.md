# PQSeal API

## `createPQSealServer(options?)`

Creates an in-memory challenge issuer and opener.

```ts
const server = createPQSealServer({
  kem,
  challengeTtlMs,
  keyRotationMs,
  challengeGenerator,
  cleanupInterval
});
```

Methods:

- `issueChallenge(): ChallengeBundle`
- `open(envelope, options?): Uint8Array`
- `openJson<T>(envelope, options?): T`
- `openFields<T>(sealedObject, options?): T`
- `cleanup(): void`
- `close(): void`

Expired challenges are cleaned automatically. `cleanupInterval` is in milliseconds and defaults to `challengeTtlMs`.

`close()` clears the cleanup timer.

## `createPQSealClient(options?)`

Creates a sealing client.

```ts
const client = createPQSealClient({
  kems: [kems.mlKem768]
});
```

Methods:

- `seal(bundle, plaintext, options?): PQSealEnvelope`
- `sealJson(bundle, value, options?): PQSealEnvelope`
- `sealFields(bundle, object, keys, options?): object`

`seal()` accepts `Uint8Array` or `string`. `sealJson()` serializes with `JSON.stringify()`.

## KEM Adapter

```ts
interface KemAdapter {
  id: string;
  keygen(): { publicKey: Uint8Array; secretKey: Uint8Array };
  encapsulate(publicKey: Uint8Array): {
    ciphertext: Uint8Array;
    sharedSecret: Uint8Array;
  };
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
}
```

Built-ins:

```ts
import { kems, mlKem768 } from 'pqseal';
```

`kems.mlKem768` is the default.

## AAD

`seal()` and `open()` accept optional AES-GCM AAD:

```ts
const envelope = client.seal(bundle, payload, { aad: 'login:v1' });
server.open(envelope, { aad: 'login:v1' });
```

AAD must match exactly on both sides.

## Errors

PQSeal throws `PQSealError` with a stable `code`:

- `BAD_OPTIONS`
- `BAD_BUNDLE`
- `BAD_ENVELOPE`
- `BAD_KEM`
- `CHALLENGE_EXPIRED`
- `CHALLENGE_REPLAYED`
- `CHALLENGE_COLLISION`
- `DECRYPT_FAILED`
