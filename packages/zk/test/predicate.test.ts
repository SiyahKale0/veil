import { randomUUID } from 'node:crypto';
import type { CredentialSchema } from '@veil/core';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  type ProofContext,
  ZkPredicateIssuer,
  ZkPredicateProver,
  ZkPredicateVerifier,
} from '../src/index.js';

// A non-age credential: prove a balance threshold without revealing the balance.
const schema = [
  { name: 'account_id', type: 'string' },
  { name: 'balance', type: 'number' },
] as const satisfies CredentialSchema;

const TYPE = 'https://veil.dev/credentials/account/v1';

let issuer: ZkPredicateIssuer;
const prover = new ZkPredicateProver(schema);

beforeAll(async () => {
  issuer = await ZkPredicateIssuer.create(schema, TYPE);
});

function context(): ProofContext {
  return { nonce: randomUUID(), audience: 'https://bank.example' };
}

describe('generic ZK predicate', () => {
  it('proves a numeric claim is at least a threshold without revealing it', async () => {
    const verifier = new ZkPredicateVerifier(schema, issuer.publicKey);
    const credential = await issuer.issue({ account_id: 'acct-1', balance: 5000 });
    const ctx = context();

    const presentation = await prover.proveAtLeast(credential, 'balance', 1000, ctx);
    expect(await verifier.verifyAtLeast(presentation, 'balance', 1000, ctx)).toBe(true);
    // The proof carries no cleartext balance.
    expect(presentation.payload).not.toContain('5000');
  });

  it('cannot prove a threshold the value does not meet', async () => {
    const credential = await issuer.issue({ account_id: 'acct-1', balance: 500 });
    await expect(prover.proveAtLeast(credential, 'balance', 1000, context())).rejects.toThrow();
  });

  it('rejects proving a non-numeric claim', async () => {
    const credential = await issuer.issue({ account_id: 'acct-1', balance: 5000 });
    await expect(prover.proveAtLeast(credential, 'account_id', 1, context())).rejects.toThrow();
  });
});
