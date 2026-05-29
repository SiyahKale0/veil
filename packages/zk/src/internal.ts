import { createRequire } from 'node:module';

// crypto-wasm-ts is CommonJS; load it via require for predictable NodeNext
// resolution. Types still come from the package declarations.
export const lib = createRequire(import.meta.url)(
  '@docknetwork/crypto-wasm-ts',
) as typeof import('@docknetwork/crypto-wasm-ts');

const encoder = new TextEncoder();
export const utf8 = (text: string): Uint8Array => encoder.encode(text);

export const toB64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url');
export const fromB64 = (text: string): Uint8Array => new Uint8Array(Buffer.from(text, 'base64url'));

/** Message layout. The age sits at AGE_INDEX and is signed as a positive integer. */
export const FIELDS = ['user_id', 'age'] as const;
export const AGE_INDEX = 1;

/** Upper bound of the range we prove the age falls in. Comfortably above any real age. */
export const MAX_AGE = 150;

const PARAMS_LABEL = utf8('veil-zk-age-params-v1');
const BPP_LABEL = utf8('veil-zk-age-bpp-v1');

let readyPromise: Promise<void> | null = null;
let sigParams: InstanceType<typeof lib.BBSSignatureParams> | null = null;
let bppParams: InstanceType<typeof lib.BoundCheckBppParams> | null = null;

export async function ensureReady(): Promise<void> {
  if (!readyPromise) {
    readyPromise = Promise.resolve(lib.initializeWasm());
  }
  await readyPromise;
}

/** Shared BBS signature params for the age credential. Call after {@link ensureReady}. */
export function getSigParams(): InstanceType<typeof lib.BBSSignatureParams> {
  if (!sigParams) {
    sigParams = lib.BBSSignatureParams.generate(FIELDS.length, PARAMS_LABEL);
  }
  return sigParams;
}

/** Transparent Bulletproofs++ params for the range proof (no trusted setup). */
export function getBppParams(): InstanceType<typeof lib.BoundCheckBppParams> {
  if (!bppParams) {
    bppParams = new lib.BoundCheckBppParams(BPP_LABEL);
  }
  return bppParams;
}

/**
 * Encodes the credential messages to field elements. The user id is hashed; the
 * age is encoded as a positive integer so a range proof can be made over it.
 */
export function encodeMessages(userId: string, age: number): Uint8Array[] {
  return [
    lib.BBSSignature.encodeMessageForSigning(utf8(userId)),
    lib.BBSSignature.encodePositiveNumberForSigning(age),
  ];
}
