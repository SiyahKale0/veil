import { ES256, type Jwk } from './webcrypto.js';

export type { Jwk };

export interface KeyPair {
  publicKey: Jwk;
  privateKey: Jwk;
}

/** Generates a fresh ES256 (P-256) key pair for an issuer or a holder. */
export function generateKeyPair(): Promise<KeyPair> {
  return ES256.generateKeyPair();
}
