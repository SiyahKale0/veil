import {
  asIntInRange,
  asObject,
  asString,
  type Credential,
  type CredentialStore,
  MAX_BLOB_BYTES,
  parseJsonObject,
  VeilError,
} from '@veil/core';
import { deriveKek, type KdfParams, open, randomKey, type SealedBytes, seal } from './crypto.js';

const VAULT_VERSION = 1;
const CHECK_TOKEN = 'veil-vault-check';

// Bounds on KDF params read from an untrusted blob, so a crafted blob cannot
// trigger an out-of-memory or runaway-CPU denial of service during unlock.
const KDF_ITER_MIN = 1;
const KDF_ITER_MAX = 10;
const KDF_MEM_MIN_KIB = 8 * 1024; // 8 MiB
const KDF_MEM_MAX_KIB = 256 * 1024; // 256 MiB
const KDF_PAR_MIN = 1;
const KDF_PAR_MAX = 16;

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

export class WrongPasswordError extends VeilError {
  constructor() {
    super('vault could not be unlocked: wrong password or corrupted blob');
  }
}

function asSealedBytes(value: unknown, field: string): SealedBytes {
  const object = asObject(value, field);
  return {
    nonce: asString(object.nonce, `${field}.nonce`),
    ciphertext: asString(object.ciphertext, `${field}.ciphertext`),
  };
}

/** Validates and bounds an untrusted vault blob before any key derivation. */
function validateBlob(blob: string): VaultBlob {
  const raw = parseJsonObject(blob, MAX_BLOB_BYTES, 'vault blob');
  asIntInRange(raw.v, VAULT_VERSION, VAULT_VERSION, 'vault blob version');

  const kdfObject = asObject(raw.kdf, 'vault blob kdf');
  const kdf: KdfParams = {
    salt: asString(kdfObject.salt, 'vault blob kdf.salt'),
    iterations: asIntInRange(
      kdfObject.iterations,
      KDF_ITER_MIN,
      KDF_ITER_MAX,
      'vault blob kdf.iterations',
    ),
    memoryKiB: asIntInRange(
      kdfObject.memoryKiB,
      KDF_MEM_MIN_KIB,
      KDF_MEM_MAX_KIB,
      'vault blob kdf.memoryKiB',
    ),
    parallelism: asIntInRange(
      kdfObject.parallelism,
      KDF_PAR_MIN,
      KDF_PAR_MAX,
      'vault blob kdf.parallelism',
    ),
  };

  const check = asSealedBytes(raw.check, 'vault blob check');

  const entriesObject = asObject(raw.entries, 'vault blob entries');
  const entries: Record<string, VaultEntry> = {};
  for (const id of Object.keys(entriesObject)) {
    const entry = asObject(entriesObject[id], `vault blob entry "${id}"`);
    entries[id] = {
      wrappedDek: asSealedBytes(entry.wrappedDek, `entry "${id}" wrappedDek`),
      data: asSealedBytes(entry.data, `entry "${id}" data`),
    };
  }

  return { v: VAULT_VERSION, kdf, check, entries };
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
    // Structure and bounds are validated first; a malformed blob throws
    // MalformedInputError. A well-formed blob that the password cannot open (or
    // that is corrupted) throws WrongPasswordError.
    const parsed = validateBlob(blob);
    try {
      const { kek } = await deriveKek(password, parsed.kdf);
      const token = decoder.decode(await open(kek, parsed.check));
      if (token !== CHECK_TOKEN) {
        throw new Error('check token mismatch');
      }
      return new EncryptedVaultStore(kek, parsed.kdf, new Map(Object.entries(parsed.entries)));
    } catch {
      throw new WrongPasswordError();
    }
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
