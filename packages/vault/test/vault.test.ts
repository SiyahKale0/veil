import { type Credential, MalformedInputError } from '@veil/core';
import { describe, expect, it } from 'vitest';
import {
  EncryptedVaultStore,
  InMemoryBlobStore,
  InMemoryVaultSync,
  type VaultBlob,
  WrongPasswordError,
} from '../src/index.js';

const PASSWORD = 'correct horse battery staple';
const SECRET = 'top-secret-credential-payload-7f3a';
const CRED: Credential = { raw: SECRET, type: 'https://veil.dev/credentials/test/v1' };

describe('encrypted vault', () => {
  it('stores and returns a credential', async () => {
    const vault = await EncryptedVaultStore.create(PASSWORD);
    await vault.put('membership', CRED);

    expect(await vault.get('membership')).toEqual(CRED);
    expect(await vault.list()).toEqual(['membership']);
  });

  it('returns null for a missing credential and supports delete', async () => {
    const vault = await EncryptedVaultStore.create(PASSWORD);
    await vault.put('a', CRED);
    await vault.delete('a');

    expect(await vault.get('a')).toBeNull();
    expect(await vault.list()).toEqual([]);
  });

  it('exports an opaque blob that carries no plaintext', async () => {
    const vault = await EncryptedVaultStore.create(PASSWORD);
    await vault.put('membership', CRED);
    const blob = await vault.export();

    expect(blob).not.toContain(SECRET);
    expect(blob).not.toContain(PASSWORD);
    expect(blob).not.toContain(CRED.type);
  });

  it('restores on another device from the synced blob', async () => {
    // Device A stores the credential and syncs the vault.
    const deviceA = await EncryptedVaultStore.create(PASSWORD);
    await deviceA.put('membership', CRED);
    const sync = new InMemoryVaultSync();
    await sync.upload('account-1', await deviceA.export());

    // The server only ever holds the opaque blob.
    const onServer = sync.storedBlob('account-1');
    expect(onServer).toBeDefined();
    expect(onServer).not.toContain(SECRET);

    // Device B restores it with the same password.
    const blob = await sync.download('account-1');
    expect(blob).not.toBeNull();
    if (!blob) return;
    const deviceB = await EncryptedVaultStore.unlock(PASSWORD, blob);
    expect(await deviceB.get('membership')).toEqual(CRED);
  });

  it('cannot be unlocked with the wrong password', async () => {
    const vault = await EncryptedVaultStore.create(PASSWORD);
    await vault.put('membership', CRED);
    const blob = await vault.export();

    await expect(EncryptedVaultStore.unlock('wrong password', blob)).rejects.toThrow(
      WrongPasswordError,
    );
  });

  it('uses a fresh DEK per credential, so identical data yields distinct ciphertexts', async () => {
    const vault = await EncryptedVaultStore.create(PASSWORD);
    await vault.put('a', CRED);
    await vault.put('b', CRED);
    const blob = JSON.parse(await vault.export()) as VaultBlob;

    expect(blob.entries.a.data.ciphertext).not.toEqual(blob.entries.b.data.ciphertext);
    expect(blob.entries.a.wrappedDek.ciphertext).not.toEqual(blob.entries.b.wrappedDek.ciphertext);
  });

  it('InMemoryBlobStore round-trips and removes', async () => {
    const store = new InMemoryBlobStore();
    expect(await store.load('k')).toBeNull();
    await store.save('k', 'blob-value');
    expect(await store.load('k')).toBe('blob-value');
    await store.remove('k');
    expect(await store.load('k')).toBeNull();
  });

  it('rejects a malformed blob', async () => {
    await expect(EncryptedVaultStore.unlock(PASSWORD, 'not json')).rejects.toThrow(
      MalformedInputError,
    );
    await expect(EncryptedVaultStore.unlock(PASSWORD, '{}')).rejects.toThrow(MalformedInputError);
  });

  it('rejects a blob with abusive KDF parameters (DoS guard)', async () => {
    const vault = await EncryptedVaultStore.create(PASSWORD);
    await vault.put('membership', CRED);
    const blob = JSON.parse(await vault.export()) as VaultBlob;

    // A crafted memory size that would exhaust memory during key derivation.
    blob.kdf.memoryKiB = 64 * 1024 * 1024;
    await expect(EncryptedVaultStore.unlock(PASSWORD, JSON.stringify(blob))).rejects.toThrow(
      MalformedInputError,
    );
  });
});
