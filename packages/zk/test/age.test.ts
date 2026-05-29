import { randomUUID } from 'node:crypto';
import { type Credential, MalformedInputError, VerificationError } from '@veil/core';
import { beforeAll, describe, expect, it } from 'vitest';
import { type ProofContext, ZkAgeIssuer, ZkAgeProver, ZkAgeVerifier } from '../src/index.js';

let issuer: ZkAgeIssuer;
const prover = new ZkAgeProver();

beforeAll(async () => {
  issuer = await ZkAgeIssuer.create();
});

function context(): ProofContext {
  return { nonce: randomUUID(), audience: 'https://bar.example' };
}

async function credential(age: number): Promise<Credential> {
  return issuer.issue({ user_id: 'u_8f3a21', age });
}

describe('zero-knowledge age predicate', () => {
  it('proves age >= 18 and the verifier only learns true/false', async () => {
    const verifier = new ZkAgeVerifier(issuer.publicKey);
    const ctx = context();
    const presentation = await prover.proveAgeAtLeast(await credential(25), 18, ctx);

    // The verifier learns a single boolean — never the age itself.
    const result = await verifier.verifyAgeAtLeast(presentation, 18, ctx);
    expect(result).toBe(true);
  });

  it('is a real predicate: age 25 proves >= 21 but not >= 26', async () => {
    const verifier = new ZkAgeVerifier(issuer.publicKey);
    const cred = await credential(25);

    const ctx = context();
    const presentation = await prover.proveAgeAtLeast(cred, 21, ctx);
    expect(await verifier.verifyAgeAtLeast(presentation, 21, ctx)).toBe(true);

    // The same age cannot be stretched past its real value.
    await expect(prover.proveAgeAtLeast(cred, 26, context())).rejects.toThrow();
  });

  it('accepts the exact boundary (age == minAge)', async () => {
    const verifier = new ZkAgeVerifier(issuer.publicKey);
    const ctx = context();
    const presentation = await prover.proveAgeAtLeast(await credential(18), 18, ctx);

    await expect(verifier.verifyAgeAtLeast(presentation, 18, ctx)).resolves.toBe(true);
  });

  it('cannot prove a threshold the age does not meet', async () => {
    const ctx = context();
    // age 16, claim >= 18: proving a false statement must not yield a usable proof
    await expect(prover.proveAgeAtLeast(await credential(16), 18, ctx)).rejects.toThrow();
  });

  it('rejects a proof replayed with a different nonce', async () => {
    const verifier = new ZkAgeVerifier(issuer.publicKey);
    const ctx = context();
    const presentation = await prover.proveAgeAtLeast(await credential(30), 18, ctx);

    await expect(
      verifier.verifyAgeAtLeast(presentation, 18, { ...ctx, nonce: randomUUID() }),
    ).rejects.toThrow(VerificationError);
  });

  it('rejects a proof aimed at a different audience', async () => {
    const verifier = new ZkAgeVerifier(issuer.publicKey);
    const ctx = context();
    const presentation = await prover.proveAgeAtLeast(await credential(30), 18, ctx);

    await expect(
      verifier.verifyAgeAtLeast(presentation, 18, { ...ctx, audience: 'https://evil.example' }),
    ).rejects.toThrow(VerificationError);
  });

  it('rejects a proof against the wrong issuer key', async () => {
    const otherIssuer = await ZkAgeIssuer.create();
    const verifier = new ZkAgeVerifier(otherIssuer.publicKey);
    const ctx = context();
    const presentation = await prover.proveAgeAtLeast(await credential(30), 18, ctx);

    await expect(verifier.verifyAgeAtLeast(presentation, 18, ctx)).rejects.toThrow(
      VerificationError,
    );
  });

  it('rejects a malformed proof payload', async () => {
    const verifier = new ZkAgeVerifier(issuer.publicKey);

    await expect(
      verifier.verifyAgeAtLeast({ format: 'zk', payload: 'not json' }, 18, context()),
    ).rejects.toThrow(MalformedInputError);
    await expect(
      verifier.verifyAgeAtLeast({ format: 'zk', payload: '{}' }, 18, context()),
    ).rejects.toThrow(MalformedInputError);
  });
});
