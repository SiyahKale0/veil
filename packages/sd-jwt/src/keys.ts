import { ES256 } from '@sd-jwt/crypto-nodejs';

/** A JWK as produced and consumed by the underlying crypto layer (ES256 / P-256). */
export type Jwk = Awaited<ReturnType<typeof ES256.generateKeyPair>>['publicKey'];

export interface KeyPair {
  publicKey: Jwk;
  privateKey: Jwk;
}

/** Generates a fresh ES256 (P-256) key pair for an issuer or a holder. */
export function generateKeyPair(): Promise<KeyPair> {
  return ES256.generateKeyPair();
}
