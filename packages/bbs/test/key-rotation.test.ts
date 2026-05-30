import { randomUUID } from 'node:crypto';
import { keyring, type PresentationRequest, VerificationError } from '@veil/core';
import { describe, expect, it } from 'vitest';
import {
  BBS_MEMBERSHIP_TYPE,
  BbsIssuer,
  BbsPresenter,
  BbsVerifier,
  membershipSchema,
} from '../src/index.js';

const CLAIMS = { user_id: 'u', email: 'a@b.c', tier: 'gold', category_sports: 'climbing' };

function request(): PresentationRequest {
  return {
    verifierId: 'https://v.example',
    requestedClaims: ['category_sports'],
    nonce: randomUUID(),
    audience: 'https://v.example',
  };
}

describe('BBS key rotation', () => {
  it('resolves the issuer key by kid', async () => {
    const issuer = await BbsIssuer.create(membershipSchema, BBS_MEMBERSHIP_TYPE, 'b2');
    const verifier = new BbsVerifier(keyring({ b2: issuer.publicKey }));

    const credential = await issuer.issue(CLAIMS);
    const req = request();
    const disclosed = await verifier.verify(await new BbsPresenter().present(req, credential), req);
    expect(disclosed.category_sports).toBe('climbing');
  });

  it('rejects an unknown kid', async () => {
    const issuer = await BbsIssuer.create(membershipSchema, BBS_MEMBERSHIP_TYPE, 'b2');
    const verifier = new BbsVerifier(keyring({ other: issuer.publicKey }));

    const credential = await issuer.issue(CLAIMS);
    const req = request();
    const presentation = await new BbsPresenter().present(req, credential);
    await expect(verifier.verify(presentation, req)).rejects.toThrow(VerificationError);
  });
});
