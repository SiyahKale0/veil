import { randomUUID } from 'node:crypto';
import { keyring, VerificationError } from 'veil-core';
import { describe, expect, it } from 'vitest';
import { type ProofContext, ZkAgeIssuer, ZkAgeProver, ZkAgeVerifier } from '../src/index.js';

function context(): ProofContext {
  return { nonce: randomUUID(), audience: 'https://v.example' };
}

describe('ZK key rotation', () => {
  it('resolves the issuer key by kid', async () => {
    const issuer = await ZkAgeIssuer.create('z2');
    const verifier = new ZkAgeVerifier(keyring({ z2: issuer.publicKey }));

    const credential = await issuer.issue({ user_id: 'u', age: 25 });
    const ctx = context();
    const presentation = await new ZkAgeProver().proveAgeAtLeast(credential, 18, ctx);
    expect(await verifier.verifyAgeAtLeast(presentation, 18, ctx)).toBe(true);
  });

  it('rejects an unknown kid', async () => {
    const issuer = await ZkAgeIssuer.create('z2');
    const verifier = new ZkAgeVerifier(keyring({ other: issuer.publicKey }));

    const credential = await issuer.issue({ user_id: 'u', age: 25 });
    const ctx = context();
    const presentation = await new ZkAgeProver().proveAgeAtLeast(credential, 18, ctx);
    await expect(verifier.verifyAgeAtLeast(presentation, 18, ctx)).rejects.toThrow(
      VerificationError,
    );
  });
});
