export function getBufferView(bytes: Uint8Array): Buffer {
  if (Buffer.isBuffer(bytes)) return bytes;
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

export function utf8ToBytes(value: string): Uint8Array {
  return Buffer.from(value, 'utf8');
}

export function bytesToUtf8(bytes: Uint8Array): string {
  return getBufferView(bytes).toString('utf8');
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function base64UrlEncode(bytes: Uint8Array): string {
  return getBufferView(bytes).toString('base64url');
}

export function base64UrlDecode(value: string): Uint8Array {
  return Buffer.from(value, 'base64url');
}

export function toBytes(value: Uint8Array | string): Uint8Array {
  return typeof value === 'string' ? utf8ToBytes(value) : value;
}
