import type { Credential, CredentialStore } from './index.js';

/**
 * Keeps credentials in process memory. The reference store for development and
 * tests; the encrypted, at-rest store arrives in a later phase behind the same
 * {@link CredentialStore} contract.
 */
export class InMemoryStore implements CredentialStore {
  private readonly items = new Map<string, Credential>();

  async put(id: string, credential: Credential): Promise<void> {
    this.items.set(id, credential);
  }

  async get(id: string): Promise<Credential | null> {
    return this.items.get(id) ?? null;
  }

  async list(): Promise<string[]> {
    return [...this.items.keys()];
  }

  async delete(id: string): Promise<void> {
    this.items.delete(id);
  }
}
