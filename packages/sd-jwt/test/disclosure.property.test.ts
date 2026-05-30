import { randomUUID } from 'node:crypto';
import fc from 'fast-check';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  generateKeyPair,
  type KeyPair,
  SdJwtIssuer,
  SdJwtPresenter,
  SdJwtVerifier,
} from '../src/index.js';

const NAMES = ['user_id', 'email', 'tier', 'category_sports'] as const;

let issuerKeys: KeyPair;
let holderKeys: KeyPair;

beforeAll(async () => {
  issuerKeys = await generateKeyPair();
  holderKeys = await generateKeyPair();
});

describe('SD-JWT disclosure invariant', () => {
  it('discloses exactly the requested claims and leaks nothing else', async () => {
    const issuer = new SdJwtIssuer('https://issuer.example', issuerKeys.privateKey);
    const presenter = new SdJwtPresenter(holderKeys.privateKey);
    const verifier = new SdJwtVerifier(issuerKeys.publicKey);

    // Distinctive hex values so an undisclosed value cannot coincidentally appear.
    const value = fc
      .uint8Array({ minLength: 6, maxLength: 8 })
      .map((bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(''));

    await fc.assert(
      fc.asyncProperty(
        fc.record({ user_id: value, email: value, tier: value, category_sports: value }),
        fc.uniqueArray(fc.constantFrom(...NAMES), { minLength: 1 }),
        async (claims, requested) => {
          const credential = await issuer.issue(claims, holderKeys.publicKey);
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
      { numRuns: 15 },
    );
  });
});
