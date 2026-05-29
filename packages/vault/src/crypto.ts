import { createRequire } from 'node:module';

// The sumo build is needed for Argon2id (crypto_pwhash); the standard build
// omits it. libsodium also ships a broken ESM build (its .mjs relative-imports a
// ./libsodium.mjs from another package), so load the working CJS build via
// require. Types come from @types/libsodium-wrappers, a subset that still covers
// everything used here.
const sodium = createRequire(import.meta.url)(
  'libsodium-wrappers-sumo',
) as typeof import('libsodium-wrappers');

type Sodium = typeof sodium;

let readyPromise: Promise<void> | null = null;

/** Resolves once the libsodium WASM module is initialized. */
async function getSodium(): Promise<Sodium> {
  if (!readyPromise) {
    readyPromise = sodium.ready;
  }
  await readyPromise;
  return sodium;
}

const b64Variant = (s: Sodium) => s.base64_variants.URLSAFE_NO_PADDING;

const toBase64 = (s: Sodium, bytes: Uint8Array): string => s.to_base64(bytes, b64Variant(s));
const fromBase64 = (s: Sodium, text: string): Uint8Array => s.from_base64(text, b64Variant(s));

/** Argon2id parameters, kept alongside the blob so the key can be re-derived. */
export interface KdfParams {
  salt: string;
  opsLimit: number;
  memLimit: number;
  alg: number;
}

/** A value encrypted with XChaCha20-Poly1305: the nonce and the ciphertext. */
export interface SealedBytes {
  nonce: string;
  ciphertext: string;
}

const KEY_BYTES = 32;

/**
 * Derives a 32-byte key encryption key (KEK) from a password with Argon2id.
 * Pass `existing` params to reproduce a previously derived key (e.g. on unlock);
 * omit them to start fresh with a new random salt.
 */
export async function deriveKek(
  password: string,
  existing?: KdfParams,
): Promise<{ kek: Uint8Array; params: KdfParams }> {
  const s = await getSodium();
  const opsLimit = existing?.opsLimit ?? s.crypto_pwhash_OPSLIMIT_INTERACTIVE;
  const memLimit = existing?.memLimit ?? s.crypto_pwhash_MEMLIMIT_INTERACTIVE;
  const alg = existing?.alg ?? s.crypto_pwhash_ALG_ARGON2ID13;
  const salt = existing
    ? fromBase64(s, existing.salt)
    : s.randombytes_buf(s.crypto_pwhash_SALTBYTES);
  const kek = s.crypto_pwhash(KEY_BYTES, password, salt, opsLimit, memLimit, alg);
  return { kek, params: { salt: toBase64(s, salt), opsLimit, memLimit, alg } };
}

/** Generates a fresh random data encryption key (DEK). */
export async function randomKey(): Promise<Uint8Array> {
  const s = await getSodium();
  return s.crypto_aead_xchacha20poly1305_ietf_keygen();
}

/** Encrypts `plaintext` under `key` with a fresh random nonce. */
export async function seal(key: Uint8Array, plaintext: Uint8Array): Promise<SealedBytes> {
  const s = await getSodium();
  const nonce = s.randombytes_buf(s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ciphertext = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    null,
    null,
    nonce,
    key,
  );
  return { nonce: toBase64(s, nonce), ciphertext: toBase64(s, ciphertext) };
}

/** Decrypts a sealed value under `key`. Throws if authentication fails. */
export async function open(key: Uint8Array, sealed: SealedBytes): Promise<Uint8Array> {
  const s = await getSodium();
  return s.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    fromBase64(s, sealed.ciphertext),
    null,
    fromBase64(s, sealed.nonce),
    key,
  );
}
