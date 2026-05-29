import { createRequire } from 'node:module';
import type { PresentationRequest } from '@veil/core';
import { FIELDS } from './membership.js';

// crypto-wasm-ts is CommonJS; load it via require so resolution is predictable
// under NodeNext. Types still come from the package declarations.
export const lib = createRequire(import.meta.url)(
  '@docknetwork/crypto-wasm-ts',
) as typeof import('@docknetwork/crypto-wasm-ts');

const encoder = new TextEncoder();
export const utf8 = (text: string): Uint8Array => encoder.encode(text);

export const toB64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url');
export const fromB64 = (text: string): Uint8Array => new Uint8Array(Buffer.from(text, 'base64url'));

// Nothing-up-my-sleeve label: signature params derive deterministically from it,
// so issuer, holder and verifier all reconstruct identical params.
const LABEL = utf8('veil-bbs-membership-v1');

let readyPromise: Promise<void> | null = null;
let params: InstanceType<typeof lib.BBSSignatureParams> | null = null;

/** Initializes the BBS WASM module once. */
export async function ensureReady(): Promise<void> {
  if (!readyPromise) {
    readyPromise = Promise.resolve(lib.initializeWasm());
  }
  await readyPromise;
}

/** The shared signature params for our fixed message layout. Call after {@link ensureReady}. */
export function getParams(): InstanceType<typeof lib.BBSSignatureParams> {
  if (!params) {
    params = lib.BBSSignatureParams.generate(FIELDS.length, LABEL);
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
  return lib.bytesToChallenge(
    concat(challengeContribution, utf8(request.nonce), utf8(request.audience)),
  );
}
