/**
 * Single-use, time-limited nonces. A verifier issues a nonce for a request and
 * consumes it on verification: an unknown, expired, or already-used nonce is
 * rejected. This is what makes a presentation fresh and non-replayable, and it
 * works the same way for every scheme because it never touches the proof itself.
 */
export interface NonceStore {
  /** Issues a fresh nonce valid for `ttlMs` (or the store's default). */
  issue(ttlMs?: number): Promise<string>;
  /** Consumes a nonce. Returns true only if it was known, unexpired and unused. */
  consume(nonce: string): Promise<boolean>;
}

const DEFAULT_TTL_MS = 5 * 60 * 1000;

/**
 * In-memory {@link NonceStore} for development and single-process verifiers.
 * A distributed verifier swaps this for a shared store (e.g. Redis) behind the
 * same interface.
 */
export class InMemoryNonceStore implements NonceStore {
  private readonly issued = new Map<string, number>();

  constructor(private readonly defaultTtlMs: number = DEFAULT_TTL_MS) {}

  async issue(ttlMs: number = this.defaultTtlMs): Promise<string> {
    this.purgeExpired();
    const nonce = globalThis.crypto.randomUUID();
    this.issued.set(nonce, Date.now() + ttlMs);
    return nonce;
  }

  async consume(nonce: string): Promise<boolean> {
    const expiresAt = this.issued.get(nonce);
    if (expiresAt === undefined) {
      return false;
    }
    this.issued.delete(nonce);
    return expiresAt >= Date.now();
  }

  private purgeExpired(): void {
    const now = Date.now();
    for (const [nonce, expiresAt] of this.issued) {
      if (expiresAt < now) {
        this.issued.delete(nonce);
      }
    }
  }
}
