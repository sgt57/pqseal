export type PQSealErrorCode =
  | 'BAD_OPTIONS'
  | 'BAD_BUNDLE'
  | 'BAD_ENVELOPE'
  | 'BAD_KEM'
  | 'CHALLENGE_EXPIRED'
  | 'CHALLENGE_REPLAYED'
  | 'CHALLENGE_COLLISION'
  | 'DECRYPT_FAILED';

export class PQSealError extends Error {
  readonly code: PQSealErrorCode;

  constructor(code: PQSealErrorCode, message: string) {
    super(message);
    this.name = 'PQSealError';
    this.code = code;
  }
}
