import { createRequire } from 'node:module';
import type { CredentialSchema, PresentationRequest } from '@veil/core';

// crypto-wasm-ts is CommonJS; load it via require for predictable NodeNext
// resolution. Types still come from the package declarations.
export const lib = createRequire(import.meta.url)(
  '@docknetwork/crypto-wasm-ts',
) as typeof import('@docknetwork/crypto-wasm-ts');

const encoder = new TextEncoder();
export const utf8 = (text: string): Uint8Array => encoder.encode(text);

export const toB64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url');
export const fromB64 = (text: string): Uint8Array => new Uint8Array(Buffer.from(text, 'base64url'));

let readyPromise: Promise<void> | null = null;
const paramsBySchema = new Map<string, InstanceType<typeof lib.BBSSignatureParams>>();

export async function ensureReady(): Promise<void> {
  if (!readyPromise) {
    readyPromise = Promise.resolve(lib.initializeWasm());
  }
  await readyPromise;
}

// Nothing-up-my-sleeve label derived from the schema, so the same schema yields
// the same params for issuer, holder and verifier, and different schemas don't.
function schemaLabel(schema: CredentialSchema): string {
  return `veil-bbs/v1/${schema.map((definition) => definition.name).join(',')}`;
}

/** Deterministic signature params for a schema. Call after {@link ensureReady}. */
export function getParams(schema: CredentialSchema): InstanceType<typeof lib.BBSSignatureParams> {
  const label = schemaLabel(schema);
  let params = paramsBySchema.get(label);
  if (!params) {
    params = lib.BBSSignatureParams.generate(schema.length, utf8(label));
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
  return lib.bytesToChallenge(
    concat(challengeContribution, utf8(request.nonce), utf8(request.audience)),
  );
}
