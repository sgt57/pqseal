# Security Notes

PQSeal is an application-layer sealing protocol for sensitive request fields. It is designed for deployments that only have ordinary HTTPS and cannot yet deploy full post-quantum or hybrid TLS end to end.

## Threat Model

PQSeal helps with passive harvest-now, decrypt-later collection of HTTPS traffic. Sensitive fields are encrypted with a fresh KEM shared secret and challenge-bound AES-GCM key material before being sent.

Replay is limited by server-side one-time challenge consumption.

## Non-Goals

PQSeal does not:

- Replace TLS or HTTPS.
- Authenticate the server by itself.
- Protect against active MITM if HTTPS/server authenticity is broken.
- Protect plaintext after your application decrypts it.
- Provide distributed replay protection across multiple servers without sticky sessions or a shared challenge store.

## Randomness

Default challenges use 128 bits from `crypto.getRandomValues()` through noble utilities. Custom challenge generators must produce unpredictable, high-entropy, collision-resistant strings.

ML-KEM encapsulation also depends on CSPRNG quality.

## KEMs

The default KEM is ML-KEM-768 via `@noble/post-quantum`. Custom KEMs can be supplied through the `KemAdapter` interface. KEM identifiers are included in the challenge bundle and envelope and are part of key derivation domain separation.

## AES-GCM and HKDF

PQSeal derives a unique AES-256-GCM key and 96-bit nonce from each KEM shared secret and challenge using HKDF-SHA512. The default protocol consumes each challenge once, so nonce reuse under the same key is avoided by construction.

## Operational Guidance

- Keep `challengeTtlMs` short. The default is 60 seconds.
- Keep key rotation between 1 minute and 24 hours. The default is 30 minutes.
- Tune `cleanupInterval` if expired challenges need to be reclaimed more or less frequently. It defaults to `challengeTtlMs`.
- Use AAD to bind envelopes to form names, endpoint versions, tenant IDs, or request context where appropriate.
- In multi-instance deployments, use sticky routing for challenge issuance/opening until a shared challenge store adapter exists.
