import { createCrypto } from './crypto-core.js';
import * as nodeEncoding from './node-encoding.js';

export const { decryptAesGcm, deriveAesMaterial, encryptAesGcm, jsonToBytes, makeFieldAad } =
  createCrypto(nodeEncoding);
