import { createCrypto } from './crypto-core.js';
import * as encoding from './encoding.js';

export const { decryptAesGcm, deriveAesMaterial, encryptAesGcm, jsonToBytes, makeFieldAad } = createCrypto(encoding);
