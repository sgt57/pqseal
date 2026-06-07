# PQSeal

PQSeal is a lightweight TypeScript library for sealing sensitive fields before they travel over conventional HTTPS. It adds a one-time, challenge-bound post-quantum encryption layer to reduce harvest-now, decrypt-later exposure when full end-to-end PQC or hybrid TLS is not available.

- PQSeal is experimental for now.
- It protects sensitive fields against passive harvest now, decrypt later attacks.
- It does not replace HTTPS or TLS.
- It does not protect against active MITM that can replace the PQSeal public key.
- It does not protect data if the private key is compromised.

## Install

```bash
pnpm add pqseal
```

## Quick Start

```ts
import { createPQSealClient, createPQSealServer } from 'pqseal';

const server = createPQSealServer();
const client = createPQSealClient();

const bundle = server.issueChallenge();
const envelope = client.sealJson(bundle, {
  cardNumber: '4111111111111111',
  cvv: '123'
});

const plaintext = server.openJson(envelope);
```

## Field Sealing

```ts
const bundle = server.issueChallenge();

const sealed = client.sealFields(
  bundle,
  { email: 'a@example.com', password: 'correct horse battery staple', remember: true },
  ['password']
);

// Send `sealed` in a normal JSON request body.
const opened = server.openFields(sealed);
```

`sealFields()` removes the selected top-level fields from the visible object and stores them inside one `__pqseal` envelope. The visible `__pqsealFields` list is authenticated as AES-GCM AAD by default, so tampering with it breaks decryption.

## Server Options

```ts
const server = createPQSealServer({
  challengeTtlMs: 60_000,
  keyRotationMs: 30 * 60_000,
  cleanupInterval: 60_000
});
```

Defaults:

- ML-KEM-768 key rotation: 30 minutes
- Allowed rotation range: 1 minute to 24 hours
- Challenge TTL: 60 seconds
- Expired challenge cleanup interval: same as `challengeTtlMs`
- Challenge entropy: 128 random bits, base64url encoded
- KDF: HKDF-SHA512
- AEAD: AES-256-GCM

## Browser Client

The client API is browser-safe ESM. The server should call `issueChallenge()` and return the bundle from an authenticated HTTPS endpoint.

```ts
import { createPQSealClient } from 'pqseal';

const client = createPQSealClient();
const bundle = await fetch('/pqseal/challenge').then((res) => res.json());

const body = client.sealFields(bundle, { username, password }, ['password']);
await fetch('/login', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify(body)
});
```

## Documentation

- [Protocol](docs/protocol.md)
- [API](docs/api.md)
- [Security](docs/security.md)
- [Node example](examples/node.mjs)
- [Browser example](examples/browser.js)
