/**
 * Isomorphic vault crypto: runs in both Node and the browser.
 *
 * - Key derivation: Argon2id (memory-hard) via hash-wasm, a cleanly packaged
 *   WebAssembly build that works in both environments.
 * - Authenticated encryption: AES-256-GCM via the Web Crypto API
 *   (`globalThis.crypto.subtle`), a platform primitive (hardware-accelerated,
 *   constant-time). ADR-0003 lists AES-256-GCM as the alternative to XChaCha20.
 *
 * No hand-rolled crypto and no Node-only modules.
 */
import { argon2id } from 'hash-wasm';

const subtle = globalThis.crypto.subtle;

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

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

/** Argon2id parameters, kept alongside the blob so the key can be re-derived. */
export interface KdfParams {
  salt: string;
  iterations: number;
  memoryKiB: number;
  parallelism: number;
}

/** A value encrypted with AES-256-GCM: the nonce (IV) and the ciphertext+tag. */
export interface SealedBytes {
  nonce: string;
  ciphertext: string;
}

const KEY_BYTES = 32;
const SALT_BYTES = 16;
const IV_BYTES = 12;

// OWASP baseline for Argon2id (m = 19 MiB, t = 2, p = 1). Tunable; benchmark per
// target device before production.
const DEFAULT_PARAMS = { iterations: 2, memoryKiB: 19_456, parallelism: 1 };

/** Argon2id tuning overrides for a fresh derivation. */
export interface KdfOptions {
  iterations?: number;
  memoryKiB?: number;
  parallelism?: number;
}

/**
 * Derives a 32-byte key encryption key (KEK) from a password with Argon2id.
 * Pass `existing` params to reproduce a previously derived key (e.g. on unlock).
 * For a fresh derivation, omit `existing`; `tuning` then overrides the defaults.
 */
export async function deriveKek(
  password: string,
  existing?: KdfParams,
  tuning?: KdfOptions,
): Promise<{ kek: Uint8Array; params: KdfParams }> {
  const salt = existing ? fromBase64Url(existing.salt) : randomBytes(SALT_BYTES);
  const iterations = existing?.iterations ?? tuning?.iterations ?? DEFAULT_PARAMS.iterations;
  const memoryKiB = existing?.memoryKiB ?? tuning?.memoryKiB ?? DEFAULT_PARAMS.memoryKiB;
  const parallelism = existing?.parallelism ?? tuning?.parallelism ?? DEFAULT_PARAMS.parallelism;
  const kek = await argon2id({
    password,
    salt,
    iterations,
    memorySize: memoryKiB,
    parallelism,
    hashLength: KEY_BYTES,
    outputType: 'binary',
  });
  return { kek, params: { salt: toBase64Url(salt), iterations, memoryKiB, parallelism } };
}

/** Generates a fresh random data encryption key (DEK). */
export async function randomKey(): Promise<Uint8Array> {
  return randomBytes(KEY_BYTES);
}

function importKey(key: Uint8Array) {
  return subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

/** Encrypts `plaintext` under `key` with a fresh random nonce. */
export async function seal(key: Uint8Array, plaintext: Uint8Array): Promise<SealedBytes> {
  const iv = randomBytes(IV_BYTES);
  const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv }, await importKey(key), plaintext);
  return { nonce: toBase64Url(iv), ciphertext: toBase64Url(new Uint8Array(ciphertext)) };
}

/** Decrypts a sealed value under `key`. Throws if authentication fails. */
export async function open(key: Uint8Array, sealed: SealedBytes): Promise<Uint8Array> {
  const plaintext = await subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64Url(sealed.nonce) },
    await importKey(key),
    fromBase64Url(sealed.ciphertext),
  );
  return new Uint8Array(plaintext);
}
