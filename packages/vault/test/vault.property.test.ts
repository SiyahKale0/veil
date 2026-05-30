import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { EncryptedVaultStore, WrongPasswordError } from '../src/index.js';

// Fast Argon2id settings so property runs stay quick; production uses the defaults.
const FAST = { iterations: 1, memoryKiB: 8192, parallelism: 1 };

const credential = fc.record({ raw: fc.string(), type: fc.string() });
const password = fc.string({ minLength: 1 });

describe('vault properties', () => {
  it('round-trips any credential under any password', async () => {
    await fc.assert(
      fc.asyncProperty(credential, password, async (cred, pw) => {
        const vault = await EncryptedVaultStore.create(pw, FAST);
        await vault.put('x', cred);
        expect(await vault.get('x')).toEqual(cred);
      }),
      { numRuns: 12 },
    );
  });

  it('never opens with a wrong password', async () => {
    await fc.assert(
      fc.asyncProperty(password, password, credential, async (pw, other, cred) => {
        fc.pre(pw !== other);
        const vault = await EncryptedVaultStore.create(pw, FAST);
        await vault.put('x', cred);
        const blob = await vault.export();
        await expect(EncryptedVaultStore.unlock(other, blob)).rejects.toThrow(WrongPasswordError);
      }),
      { numRuns: 12 },
    );
  });
});
