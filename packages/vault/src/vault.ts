import type { Credential, CredentialStore } from '@veil/core';
import {
  deriveKek,
  open,
  randomKey,
  seal,
  type KdfParams,
  type SealedBytes,
} from './crypto.js';

const VAULT_VERSION = 1;
const CHECK_TOKEN = 'veil-vault-check';

/** One stored credential: its DEK wrapped by the KEK, and its data under the DEK. */
interface VaultEntry {
  wrappedDek: SealedBytes;
  data: SealedBytes;
}

/**
 * The opaque, fully-encrypted form of a vault. This is the only thing that ever
 * leaves the device — it holds no plaintext, no password and no key.
 */
export interface VaultBlob {
  v: number;
  kdf: KdfParams;
  /** CHECK_TOKEN sealed with the KEK; lets unlock detect a wrong password. */
  check: SealedBytes;
  entries: Record<string, VaultEntry>;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export class WrongPasswordError extends Error {
  constructor() {
    super('vault could not be unlocked: wrong password or corrupted blob');
    this.name = 'WrongPasswordError';
  }
}

/**
 * A {@link CredentialStore} that keeps every credential encrypted at rest.
 *
 * Envelope encryption: each credential gets its own random DEK (so one leaked
 * key exposes one credential, not the vault), and every DEK is wrapped by a KEK
 * derived from the user's password with Argon2id. The server only ever holds
 * the {@link VaultBlob}; the password and keys never leave the device.
 */
export class EncryptedVaultStore implements CredentialStore {
  private constructor(
    private readonly kek: Uint8Array,
    private readonly kdf: KdfParams,
    private readonly entries: Map<string, VaultEntry>,
  ) {}

  /** Creates a fresh, empty vault locked by `password`. */
  static async create(password: string): Promise<EncryptedVaultStore> {
    const { kek, params } = await deriveKek(password);
    return new EncryptedVaultStore(kek, params, new Map());
  }

  /**
   * Unlocks a vault from its opaque blob. This is how a credential is restored
   * on another device: the same password plus the synced blob. Throws
   * {@link WrongPasswordError} if the password does not match.
   */
  static async unlock(password: string, blob: string): Promise<EncryptedVaultStore> {
    const parsed = JSON.parse(blob) as VaultBlob;
    const { kek } = await deriveKek(password, parsed.kdf);
    try {
      const token = decoder.decode(await open(kek, parsed.check));
      if (token !== CHECK_TOKEN) {
        throw new Error('check token mismatch');
      }
    } catch {
      throw new WrongPasswordError();
    }
    return new EncryptedVaultStore(kek, parsed.kdf, new Map(Object.entries(parsed.entries)));
  }

  async put(id: string, credential: Credential): Promise<void> {
    const dek = await randomKey();
    const data = await seal(dek, encoder.encode(JSON.stringify(credential)));
    const wrappedDek = await seal(this.kek, dek);
    this.entries.set(id, { wrappedDek, data });
  }

  async get(id: string): Promise<Credential | null> {
    const entry = this.entries.get(id);
    if (!entry) {
      return null;
    }
    const dek = await open(this.kek, entry.wrappedDek);
    const plaintext = await open(dek, entry.data);
    return JSON.parse(decoder.decode(plaintext)) as Credential;
  }

  async list(): Promise<string[]> {
    return [...this.entries.keys()];
  }

  async delete(id: string): Promise<void> {
    this.entries.delete(id);
  }

  /** Serializes the vault to an opaque, fully-encrypted blob for storage or sync. */
  async export(): Promise<string> {
    const check = await seal(this.kek, encoder.encode(CHECK_TOKEN));
    const blob: VaultBlob = {
      v: VAULT_VERSION,
      kdf: this.kdf,
      check,
      entries: Object.fromEntries(this.entries),
    };
    return JSON.stringify(blob);
  }
}
