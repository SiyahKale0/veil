import type { CredentialSchema, PresentationRequest } from '@veil/core';

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

let libRef: Lib | null = null;
let readyPromise: Promise<void> | null = null;
const paramsBySchema = new Map<string, InstanceType<Lib['BBSSignatureParams']>>();

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
    throw new Error('BBS module is not initialized; await ensureReady() first');
  }
  return libRef;
}

// Nothing-up-my-sleeve label derived from the schema, so the same schema yields
// the same params for issuer, holder and verifier, and different schemas don't.
function schemaLabel(schema: CredentialSchema): string {
  return `veil-bbs/v1/${schema.map((definition) => definition.name).join(',')}`;
}

/** Deterministic signature params for a schema. Call after {@link ensureReady}. */
export function getParams(schema: CredentialSchema): InstanceType<Lib['BBSSignatureParams']> {
  const label = schemaLabel(schema);
  let params = paramsBySchema.get(label);
  if (!params) {
    params = getLib().BBSSignatureParams.generate(schema.length, utf8(label));
    paramsBySchema.set(label, params);
  }
  return params;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/**
 * The Fiat-Shamir challenge, bound to the verifier's nonce and audience so a
 * proof cannot be replayed or redirected to a different verifier.
 */
export function challenge(
  challengeContribution: Uint8Array,
  request: PresentationRequest,
): Uint8Array {
  return getLib().bytesToChallenge(
    concat(challengeContribution, utf8(request.nonce), utf8(request.audience)),
  );
}
