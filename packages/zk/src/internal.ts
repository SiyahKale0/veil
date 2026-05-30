/** The crypto-wasm-ts module type. */
export type Lib = typeof import('@docknetwork/crypto-wasm-ts');

const encoder = new TextEncoder();
export const utf8 = (text: string): Uint8Array => encoder.encode(text);

// Isomorphic base64url (no Node Buffer), so this runs in the browser too.
export const toB64 = (bytes: Uint8Array): string => {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

export const fromB64 = (text: string): Uint8Array => {
  const binary = atob(text.replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
};

/**
 * Message layout: user id, then the age (signed as a positive integer so it can
 * be range-proven), then the expiry (also a positive integer, revealed in the
 * proof so the verifier can enforce it).
 */
export const FIELDS = ['user_id', 'age', 'exp'] as const;
export const AGE_INDEX = 1;
export const EXP_INDEX = 2;

/** Upper bound of the range we prove the age falls in. Comfortably above any real age. */
export const MAX_AGE = 150;

/** Default credential lifetime: one year. */
export const DEFAULT_VALIDITY_SECONDS = 365 * 24 * 60 * 60;

const PARAMS_LABEL = utf8('veil-zk-age-params-v2');
const BPP_LABEL = utf8('veil-zk-age-bpp-v1');

let libRef: Lib | null = null;
let readyPromise: Promise<void> | null = null;
let sigParams: InstanceType<Lib['BBSSignatureParams']> | null = null;
let bppParams: InstanceType<Lib['BoundCheckBppParams']> | null = null;

// The WASM loader inside crypto-wasm-ts references Node's `Buffer`, which a
// browser lacks. Provide it (guarded, only when missing) so the package works in
// a browser with no setup from the caller. In Node the `buffer` import is never
// reached because `globalThis.Buffer` already exists.
async function ensureBuffer(): Promise<void> {
  const scope = globalThis as { Buffer?: unknown };
  if (typeof scope.Buffer === 'undefined') {
    const { Buffer } = await import('buffer');
    scope.Buffer = Buffer;
  }
}

// Loaded via a plain dynamic import (not Node's require) so a bundler can resolve
// it for the browser; crypto-wasm-ts is CommonJS, so the module sits on `default`
// in some loaders and on the namespace in others.
async function load(): Promise<void> {
  await ensureBuffer();
  const mod = await import('@docknetwork/crypto-wasm-ts');
  const lib = ((mod as { default?: Lib }).default ?? mod) as Lib;
  await lib.initializeWasm();
  libRef = lib;
}

export async function ensureReady(): Promise<void> {
  if (!readyPromise) {
    readyPromise = load();
  }
  await readyPromise;
}

/** The initialized crypto-wasm-ts module. Call after {@link ensureReady}. */
export function getLib(): Lib {
  if (!libRef) {
    throw new Error('ZK module is not initialized; await ensureReady() first');
  }
  return libRef;
}

/** Shared BBS signature params for the age credential. Call after {@link ensureReady}. */
export function getSigParams(): InstanceType<Lib['BBSSignatureParams']> {
  if (!sigParams) {
    sigParams = getLib().BBSSignatureParams.generate(FIELDS.length, PARAMS_LABEL);
  }
  return sigParams;
}

/** Transparent Bulletproofs++ params for the range proof (no trusted setup). */
export function getBppParams(): InstanceType<Lib['BoundCheckBppParams']> {
  if (!bppParams) {
    bppParams = new (getLib().BoundCheckBppParams)(BPP_LABEL);
  }
  return bppParams;
}

/**
 * Encodes the credential messages to field elements. The user id is hashed; the
 * age is encoded as a positive integer so a range proof can be made over it.
 */
export function encodeMessages(userId: string, age: number, exp: number): Uint8Array[] {
  const lib = getLib();
  return [
    lib.BBSSignature.encodeMessageForSigning(utf8(userId)),
    lib.BBSSignature.encodePositiveNumberForSigning(age),
    lib.BBSSignature.encodePositiveNumberForSigning(exp),
  ];
}

/** Encodes a number as the same field element used for the expiry message. */
export function encodeNumber(value: number): Uint8Array {
  return getLib().BBSSignature.encodePositiveNumberForSigning(value);
}
