import type { ClaimValues, CredentialSchema } from 'veil-core';

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
 * Message layout: the schema's claims (string claims hashed, number claims signed
 * as positive integers so they can be range-proven), then a reserved expiry slot
 * at the end, revealed in the proof so the verifier can enforce it.
 */
export const expIndex = (schema: CredentialSchema): number => schema.length;

/** Exclusive upper bound for range proofs (covers ages, years, counts, etc.). */
export const DEFAULT_UPPER_BOUND = 2 ** 32;

/** Default credential lifetime: one year. */
export const DEFAULT_VALIDITY_SECONDS = 365 * 24 * 60 * 60;

const BPP_LABEL = utf8('veil-zk-bpp-v1');

let libRef: Lib | null = null;
let readyPromise: Promise<void> | null = null;
const sigParamsBySchema = new Map<string, InstanceType<Lib['BBSSignatureParams']>>();
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

function schemaLabel(schema: CredentialSchema): string {
  return `veil-zk/v1/${schema.map((d) => `${d.name}:${d.type}`).join(',')}+exp`;
}

/** Deterministic BBS params for a schema (claims + reserved expiry). Call after {@link ensureReady}. */
export function getSigParams(schema: CredentialSchema): InstanceType<Lib['BBSSignatureParams']> {
  const label = schemaLabel(schema);
  let params = sigParamsBySchema.get(label);
  if (!params) {
    params = getLib().BBSSignatureParams.generate(schema.length + 1, utf8(label));
    sigParamsBySchema.set(label, params);
  }
  return params;
}

/** Transparent Bulletproofs++ params for the range proof (no trusted setup). */
export function getBppParams(): InstanceType<Lib['BoundCheckBppParams']> {
  if (!bppParams) {
    bppParams = new (getLib().BoundCheckBppParams)(BPP_LABEL);
  }
  return bppParams;
}

/** Encodes a number as a positive-integer field element (for the bounded claim and expiry). */
export function encodeNumber(value: number): Uint8Array {
  return getLib().BBSSignature.encodePositiveNumberForSigning(value);
}

/**
 * Encodes the schema's claims to field elements: string claims are hashed, number
 * claims are encoded as positive integers so they can be range-proven.
 */
export function encodeClaims(schema: CredentialSchema, values: ClaimValues): Uint8Array[] {
  const lib = getLib();
  return schema.map((definition) => {
    const value = values[definition.name];
    return definition.type === 'number'
      ? lib.BBSSignature.encodePositiveNumberForSigning(value as number)
      : lib.BBSSignature.encodeMessageForSigning(utf8(String(value)));
  });
}
