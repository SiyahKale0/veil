import { randomUUID } from 'node:crypto';
import fc from 'fast-check';
import { beforeAll, describe, expect, it } from 'vitest';
import { BbsIssuer, BbsPresenter, BbsVerifier } from '../src/index.js';

const NAMES = ['user_id', 'email', 'tier', 'category_sports'] as const;

let issuer: BbsIssuer;

beforeAll(async () => {
  issuer = await BbsIssuer.create();
});

describe('BBS disclosure invariant', () => {
  it('discloses exactly the requested claims and leaks nothing else', async () => {
    const presenter = new BbsPresenter();
    const verifier = new BbsVerifier(issuer.publicKey);
    const value = fc
      .uint8Array({ minLength: 6, maxLength: 8 })
      .map((bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(''));

    await fc.assert(
      fc.asyncProperty(
        fc.record({ user_id: value, email: value, tier: value, category_sports: value }),
        fc.uniqueArray(fc.constantFrom(...NAMES), { minLength: 1 }),
        async (claims, requested) => {
          const credential = await issuer.issue(claims);
          const req = {
            verifierId: 'https://v.example',
            requestedClaims: [...requested],
            nonce: randomUUID(),
            audience: 'https://v.example',
          };
          const presentation = await presenter.present(req, credential);
          const disclosed = await verifier.verify(presentation, req);

          for (const name of requested) {
            expect(disclosed[name]).toBe(claims[name]);
          }
          for (const name of NAMES.filter((n) => !requested.includes(n))) {
            expect(disclosed[name]).toBeUndefined();
            expect(presentation.payload).not.toContain(claims[name]);
          }
        },
      ),
      { numRuns: 8 },
    );
  });
});
