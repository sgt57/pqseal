import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

import type { KemAdapter } from './types.js';

export const mlKem768: KemAdapter = {
  id: 'ml-kem-768',
  keygen() {
    return ml_kem768.keygen();
  },
  encapsulate(publicKey) {
    const result = ml_kem768.encapsulate(publicKey);
    return {
      ciphertext: result.cipherText,
      sharedSecret: result.sharedSecret
    };
  },
  decapsulate(ciphertext, secretKey) {
    return ml_kem768.decapsulate(ciphertext, secretKey);
  }
};

export const kems = {
  mlKem768
} as const;
