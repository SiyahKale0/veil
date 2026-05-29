import { randomUUID } from 'node:crypto';
import type { Credential, Presenter, Verifier } from '@veil/core';
import { generateKeyPair, SdJwtIssuer, SdJwtPresenter, SdJwtVerifier } from '@veil/sd-jwt';
import { describe, expect, it } from 'vitest';
import { BbsIssuer, BbsPresenter, BbsVerifier } from '../src/index.js';

const CLAIMS = {
  user_id: 'u_1',
  email: 'ada@example.com',
  tier: 'gold',
  category_sports: 'climbing',
};

interface Scheme {
  name: string;
  setup(): Promise<{ credential: Credential; presenter: Presenter; verifier: Verifier }>;
}

// Both schemes are wired up only through the shared @veil/core contracts.
const schemes: Scheme[] = [
  {
    name: 'sd-jwt',
    async setup() {
      const issuerKeys = await generateKeyPair();
      const holderKeys = await generateKeyPair();
      const issuer = new SdJwtIssuer('https://issuer.veil.dev', issuerKeys.privateKey);
      const credential = await issuer.issue(CLAIMS, holderKeys.publicKey);
      return {
        credential,
        presenter: new SdJwtPresenter(holderKeys.privateKey),
        verifier: new SdJwtVerifier(issuerKeys.publicKey),
      };
    },
  },
  {
    name: 'bbs',
    async setup() {
      const issuer = await BbsIssuer.create();
      const credential = await issuer.issue(CLAIMS);
      return {
        credential,
        presenter: new BbsPresenter(),
        verifier: new BbsVerifier(issuer.publicKey),
      };
    },
  },
];

describe.each(schemes)('Presenter/Verifier contract: $name', (scheme) => {
  it('discloses the requested claim through the shared interface', async () => {
    const { credential, presenter, verifier } = await scheme.setup();
    const request = {
      verifierId: 'https://v.example',
      requestedClaims: ['category_sports'],
      nonce: randomUUID(),
      audience: 'https://v.example',
    };

    const presentation = await presenter.present(request, credential);
    const disclosed = await verifier.verify(presentation, request);

    expect(disclosed.category_sports).toBe('climbing');
  });
});
