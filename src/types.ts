export type Bytes = Uint8Array;

export interface KemKeyPair {
  publicKey: Bytes;
  secretKey: Bytes;
}

export interface KemEncapsulation {
  ciphertext: Bytes;
  sharedSecret: Bytes;
}

export interface KemAdapter {
  id: string;
  keygen(): KemKeyPair;
  encapsulate(publicKey: Bytes): KemEncapsulation;
  decapsulate(ciphertext: Bytes, secretKey: Bytes): Bytes;
}

export interface ChallengeBundle {
  v: 1;
  kem: string;
  publicKey: string;
  challenge: string;
  expiresAt: number;
}

export interface PQSealEnvelope {
  v: 1;
  kem: string;
  challenge: string;
  ciphertext: string;
  data: string;
}

export interface SealOptions {
  aad?: Bytes | string;
}

export interface OpenOptions {
  aad?: Bytes | string;
}

export interface FieldSealedObject {
  [key: string]: unknown;
  __pqseal: PQSealEnvelope;
  __pqsealFields: string[];
}

export type ChallengeGenerator = () => string;

export interface PQSealServerOptions {
  kem?: KemAdapter;
  challengeTtlMs?: number;
  keyRotationMs?: number;
  challengeGenerator?: ChallengeGenerator;
  now?: () => number;
  autoCleanup?: boolean;
  cleanupIntervalMs?: number;
}

export interface PQSealClientOptions {
  kems?: Iterable<KemAdapter>;
}

export interface PQSealServer {
  issueChallenge(): ChallengeBundle;
  open(envelope: PQSealEnvelope, options?: OpenOptions): Bytes;
  openJson<T = unknown>(envelope: PQSealEnvelope, options?: OpenOptions): T;
  openFields<T extends Record<string, unknown>>(sealedObject: FieldSealedObject, options?: OpenOptions): T;
  cleanup(): number;
  close(): void;
}

export interface PQSealClient {
  seal(bundle: ChallengeBundle, plaintext: Bytes | string, options?: SealOptions): PQSealEnvelope;
  sealJson(bundle: ChallengeBundle, value: unknown, options?: SealOptions): PQSealEnvelope;
  sealFields<T extends Record<string, unknown>, K extends keyof T>(
    bundle: ChallengeBundle,
    object: T,
    keys: readonly K[],
    options?: SealOptions
  ): Omit<T, K> & FieldSealedObject;
}
