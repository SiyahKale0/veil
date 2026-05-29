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

/** Persists the holder's credentials. */
export interface CredentialStore {
  put(id: string, credential: Credential): Promise<void>;
  get(id: string): Promise<Credential | null>;
  list(): Promise<string[]>;
  delete(id: string): Promise<void>;
}

/** Raised when a presentation fails verification. */
export class VerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VerificationError';
  }
}

export { InMemoryStore } from './memory-store.js';
