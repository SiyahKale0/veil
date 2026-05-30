import { EncryptedVaultStore, IndexedDbBlobStore } from 'veil-vault';
import { describe, expect, it } from 'vitest';

describe('vault persistence (IndexedDB)', () => {
  it('saves the encrypted blob and restores it across a fresh store', async () => {
    const password = 'correct horse battery staple';
    const blobs = new IndexedDbBlobStore('veil-test', 'vault');

    // Create a vault, store a credential, and persist the encrypted blob.
    const vault = await EncryptedVaultStore.create(password, { memoryKiB: 8192, iterations: 1 });
    await vault.put('membership', { raw: 'secret-token', type: 'https://veil.dev/test' });
    await blobs.save('ada', await vault.export());

    // A later session loads the blob and unlocks it.
    const stored = await blobs.load('ada');
    expect(stored).not.toBeNull();
    if (!stored) return;
    expect(stored).not.toContain('secret-token');

    const restored = await EncryptedVaultStore.unlock(password, stored);
    expect((await restored.get('membership'))?.raw).toBe('secret-token');

    await blobs.remove('ada');
    expect(await blobs.load('ada')).toBeNull();
  });
});
