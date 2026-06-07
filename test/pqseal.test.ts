import { describe, expect, it } from 'vitest';

import {
  PQSealError,
  base64UrlDecode,
  base64UrlEncode,
  bytesToUtf8,
  createPQSealClient,
  createPQSealServer,
  type KemAdapter
} from '../src/index.js';

const textEncoder = new TextEncoder();

function expectPQSealCode(error: unknown, code: string): void {
  expect(error).toBeInstanceOf(PQSealError);
  expect((error as PQSealError).code).toBe(code);
}

function fakeKem(id = 'fake-kem'): KemAdapter {
  return {
    id,
    keygen() {
      return {
        publicKey: new Uint8Array([1, 2, 3, 4]),
        secretKey: new Uint8Array([4, 3, 2, 1])
      };
    },
    encapsulate(publicKey) {
      return {
        ciphertext: new Uint8Array(publicKey),
        sharedSecret: textEncoder.encode(`shared:${id}`)
      };
    },
    decapsulate() {
      return textEncoder.encode(`shared:${id}`);
    }
  };
}

describe('PQSeal', () => {
  it('round-trips bytes and rejects replay', () => {
    const server = createPQSealServer();
    const client = createPQSealClient();
    const bundle = server.issueChallenge();
    const envelope = client.seal(bundle, new Uint8Array([1, 2, 3]), { aad: 'login-form' });

    expect([...server.open(envelope, { aad: 'login-form' })]).toEqual([1, 2, 3]);
    expect(() => server.open(envelope, { aad: 'login-form' })).toThrow(PQSealError);
  });

  it('round-trips strings and JSON', () => {
    const server = createPQSealServer();
    const client = createPQSealClient();

    const stringEnvelope = client.seal(server.issueChallenge(), 'secret');
    expect(bytesToUtf8(server.open(stringEnvelope))).toBe('secret');

    const jsonEnvelope = client.sealJson(server.issueChallenge(), { token: 'abc', n: 3 });
    expect(server.openJson(jsonEnvelope)).toEqual({ token: 'abc', n: 3 });
  });

  it('rejects expired challenges and cleans them up', () => {
    let now = 1_000;
    const server = createPQSealServer({ challengeTtlMs: 10, now: () => now });
    const client = createPQSealClient();
    const envelope = client.seal(server.issueChallenge(), 'late');

    now = 1_011;
    expect(() => server.open(envelope)).toThrow(PQSealError);
    try {
      server.open(envelope);
    } catch (error) {
      expectPQSealCode(error, 'CHALLENGE_REPLAYED');
    }
  });

  it('regenerates challenge collisions while previous challenge is alive', () => {
    const values = ['same', 'same', 'next'];
    const server = createPQSealServer({
      challengeGenerator: () => values.shift() ?? 'fallback'
    });

    expect(server.issueChallenge().challenge).toBe('same');
    expect(server.issueChallenge().challenge).toBe('next');
  });

  it('preserves issued challenge decryptability across key rotation', () => {
    let now = 10_000;
    const server = createPQSealServer({ keyRotationMs: 60_000, challengeTtlMs: 120_000, now: () => now });
    const client = createPQSealClient();
    const first = server.issueChallenge();

    now += 61_000;
    const second = server.issueChallenge();
    expect(second.publicKey).not.toBe(first.publicKey);

    const envelope = client.seal(first, 'still valid');
    expect(bytesToUtf8(server.open(envelope))).toBe('still valid');
  });

  it('rejects tampered data, ciphertext, challenge, and aad', () => {
    const client = createPQSealClient();

    const tamperCases = [
      (envelope: ReturnType<typeof client.seal>) => ({ ...envelope, data: base64UrlEncode(new Uint8Array([9, 9, 9])) }),
      (envelope: ReturnType<typeof client.seal>) => ({ ...envelope, ciphertext: base64UrlEncode(new Uint8Array([8, 8, 8])) }),
      (envelope: ReturnType<typeof client.seal>) => ({ ...envelope, challenge: 'different' })
    ];

    for (const tamper of tamperCases) {
      const server = createPQSealServer();
      const envelope = client.seal(server.issueChallenge(), 'secret', { aad: 'aad' });
      expect(() => server.open(tamper(envelope), { aad: 'aad' })).toThrow(PQSealError);
    }

    const server = createPQSealServer();
    const envelope = client.seal(server.issueChallenge(), 'secret', { aad: 'aad' });
    expect(() => server.open(envelope, { aad: 'other' })).toThrow(PQSealError);
  });

  it('seals and opens selected top-level fields', () => {
    const server = createPQSealServer();
    const client = createPQSealClient();
    const sealed = client.sealFields(server.issueChallenge(), { email: 'a@example.com', password: 'pw', keep: 1 }, [
      'password'
    ]);

    expect(sealed.password).toBeUndefined();
    expect(sealed.keep).toBe(1);
    expect(sealed.__pqsealFields).toEqual(['password']);
    expect(server.openFields<typeof sealed>(sealed)).toMatchObject({
      email: 'a@example.com',
      password: 'pw',
      keep: 1
    });
  });

  it('supports custom KEM adapters', () => {
    const kem = fakeKem();
    const server = createPQSealServer({ kem });
    const client = createPQSealClient({ kems: [kem] });
    const envelope = client.seal(server.issueChallenge(), 'custom');

    expect(bytesToUtf8(server.open(envelope))).toBe('custom');
  });

  it('exports base64url helpers for envelope integrations', () => {
    const bytes = new Uint8Array([0, 255, 4, 5]);
    expect([...base64UrlDecode(base64UrlEncode(bytes))]).toEqual([...bytes]);
  });
});
