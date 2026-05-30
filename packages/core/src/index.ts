/**
 * Core contracts shared across credential schemes.
 *
 * These interfaces are the seams that let one scheme be swapped for another
 * without touching calling code: an SD-JWT presenter today, a BBS presenter
 * later, both behind {@link Presenter}.
 */

/** A credential held by the user, in its compact serialized form. */
export interface Credential {
  /** Compact serialized credential (for SD-JWT-VC, the issued token). */
  readonly raw: string;
  /** Credential type identifier (the `vct` for SD-JWT-VC). */
  readonly type: string;
}

/** What a verifier asks the holder to present. */
export interface PresentationRequest {
  /** Who is asking. Used to derive a per-verifier (pairwise) binding. */
  verifierId: string;
  /** Claims the verifier wants disclosed. Anything else stays hidden. */
  requestedClaims: string[];
  /** One-time value chosen by the verifier; binds the proof, blocks replay. */
  nonce: string;
  /** Intended audience of the proof (the key-binding `aud`). */
  audience: string;
}

/** Claims that ended up being revealed to the verifier. */
export type DisclosedClaims = Record<string, unknown>;

/** A proof produced for a single presentation request. */
export interface Presentation {
  /** Which scheme produced this proof. */
  format: 'sd-jwt-vc' | 'bbs' | 'zk';
  /** Scheme-specific proof, compact serialized. */
  payload: string;
}

/**
 * Produces a presentation from a held credential.
 *
 * Implementations: `SdJwtPresenter` (now), `BbsPresenter`, `ZkPresenter` (later).
 */
export interface Presenter {
  present(request: PresentationRequest, credential: Credential): Promise<Presentation>;
}

/** Verifies a presentation and returns only what was disclosed. Throws on any failure. */
export interface Verifier {
  verify(presentation: Presentation, request: PresentationRequest): Promise<DisclosedClaims>;
}

/** The user's answer to a verifier's request. */
export interface ConsentDecision {
  /** Whether the user agreed to share anything at all. */
  approved: boolean;
  /** The subset of requested claims the user agreed to disclose. */
  approvedClaims: string[];
}

/** Asks the user whether, and what, to disclose for a given request. */
export interface ConsentManager {
  request(request: PresentationRequest): Promise<ConsentDecision>;
}

/** Persists the holder's credentials. */
export interface CredentialStore {
  put(id: string, credential: Credential): Promise<void>;
  get(id: string): Promise<Credential | null>;
  list(): Promise<string[]>;
  delete(id: string): Promise<void>;
}

export { ConsentDeniedError, MalformedInputError, VeilError, VerificationError } from './errors.js';
export { type KeyResolver, keyring } from './keyring.js';
export { InMemoryStore } from './memory-store.js';
export { InMemoryNonceStore, type NonceStore } from './nonce-store.js';
export {
  type ClaimDefinition,
  type ClaimType,
  type ClaimValues,
  type CredentialSchema,
  claimNames,
  validateClaims,
} from './schema.js';
export {
  asIntInRange,
  asObject,
  asString,
  asStringArray,
  asStringRecord,
  assertWithinSize,
  MAX_BLOB_BYTES,
  MAX_PAYLOAD_BYTES,
  parseJsonObject,
} from './validation.js';
