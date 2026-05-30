/**
 * Isomorphic crypto for SD-JWT, built on the Web Crypto API (`crypto.subtle`),
 * which is present in both browsers and modern Node. No WASM, no Node-only
 * modules — this is what keeps the SD-JWT path running in a browser wallet.
 *
 * This is not hand-rolled crypto: signing, verification, hashing and randomness
 * all come from the platform's audited primitives. We only adapt them to the
 * function shapes the SD-JWT library expects.
 */

// Type-only import: erased at compile time, so the emitted code stays isomorphic
// (it touches only globalThis.crypto). The types just describe the Web Crypto API.
import type { webcrypto } from 'node:crypto';

const subtle = globalThis.crypto.subtle;

/** A P-256 JWK. */
export type Jwk = webcrypto.JsonWebKey;

const ES256_PARAMS = { name: 'ECDSA', namedCurve: 'P-256' };
const ES256_SIGN = { name: 'ECDSA', hash: 'SHA-256' };

const encoder = new TextEncoder();

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(text: string): Uint8Array {
  const binary = atob(text.replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function normalizeHashAlg(alg: string): string {
  const upper = alg.toUpperCase();
  return upper.startsWith('SHA') && !upper.includes('-') ? `SHA-${upper.slice(3)}` : upper;
}

/** ES256 (ECDSA P-256) helpers in the shape the SD-JWT library expects. */
export const ES256 = {
  alg: 'ES256',

  async generateKeyPair(): Promise<{ publicKey: Jwk; privateKey: Jwk }> {
    const pair = await subtle.generateKey(ES256_PARAMS, true, ['sign', 'verify']);
    const [publicKey, privateKey] = await Promise.all([
      subtle.exportKey('jwk', pair.publicKey),
      subtle.exportKey('jwk', pair.privateKey),
    ]);
    return { publicKey, privateKey };
  },

  async getSigner(privateKeyJwk: Jwk): Promise<(data: string) => Promise<string>> {
    const key = await subtle.importKey('jwk', privateKeyJwk, ES256_PARAMS, false, ['sign']);
    return async (data: string) => {
      const signature = await subtle.sign(ES256_SIGN, key, encoder.encode(data));
      return toBase64Url(new Uint8Array(signature));
    };
  },

  async getVerifier(
    publicKeyJwk: Jwk,
  ): Promise<(data: string, signatureBase64url: string) => Promise<boolean>> {
    const key = await subtle.importKey('jwk', publicKeyJwk, ES256_PARAMS, false, ['verify']);
    return async (data: string, signatureBase64url: string) =>
      subtle.verify(ES256_SIGN, key, fromBase64Url(signatureBase64url), encoder.encode(data));
  },
};

/** SHA hasher in the shape the SD-JWT library expects (async is fine). */
export async function digest(
  data: string | ArrayBuffer,
  algorithm = 'sha-256',
): Promise<Uint8Array> {
  const bytes = typeof data === 'string' ? encoder.encode(data) : new Uint8Array(data);
  const hash = await subtle.digest(normalizeHashAlg(algorithm), bytes);
  return new Uint8Array(hash);
}

/** Random salt of `length` bytes, base64url-encoded. */
export function generateSalt(length: number): string {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}
