/**
 * A stand-in for the sync server. It only ever holds opaque vault blobs — never
 * a password, a key or any plaintext. Real sync swaps this for a network client
 * behind the same shape, which is exactly why it can stay zero-knowledge.
 */
export class InMemoryVaultSync {
  private readonly blobs = new Map<string, string>();

  async upload(accountId: string, blob: string): Promise<void> {
    this.blobs.set(accountId, blob);
  }

  async download(accountId: string): Promise<string | null> {
    return this.blobs.get(accountId) ?? null;
  }

  /** Everything the server can possibly see for an account — used in tests and demos. */
  storedBlob(accountId: string): string | undefined {
    return this.blobs.get(accountId);
  }
}
