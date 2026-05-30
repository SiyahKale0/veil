import { randomUUID } from 'node:crypto';
import {
  InMemoryNonceStore,
  MalformedInputError,
  type PresentationRequest,
  VerificationError,
} from 'veil-core';
import { beforeAll, describe, expect, it } from 'vitest';
import { BbsIssuer, BbsPresenter, BbsVerifier, type MembershipClaims } from '../src/index.js';

const CLAIMS: MembershipClaims = {
  user_id: 'u_8f3a21',
  email: 'ada@example.com',
  tier: 'gold',
  category_sports: 'climbing',
};

let issuer: BbsIssuer;

beforeAll(async () => {
  issuer = await BbsIssuer.create();
});

function request(overrides: Partial<PresentationRequest> = {}): PresentationRequest {
  return {
    verifierId: 'https://gym.example',
    requestedClaims: ['category_sports'],
    nonce: randomUUID(),
    audience: 'https://gym.example',
    ...overrides,
  };
}

describe('BBS selective disclosure', () => {
  it('discloses the requested claim and verifies', async () => {
    const presenter = new BbsPresenter();
    const verifier = new BbsVerifier(issuer.publicKey);

    const credential = await issuer.issue(CLAIMS);
    const req = request();
    const presentation = await presenter.present(req, credential);
    const disclosed = await verifier.verify(presentation, req);

    expect(disclosed.category_sports).toBe('climbing');
  });

  it('never reveals the hidden claims', async () => {
    const presenter = new BbsPresenter();
    const verifier = new BbsVerifier(issuer.publicKey);

    const credential = await issuer.issue(CLAIMS);
    const req = request();
    const presentation = await presenter.present(req, credential);
    const disclosed = await verifier.verify(presentation, req);

    expect(disclosed.user_id).toBeUndefined();
    expect(disclosed.email).toBeUndefined();
    expect(disclosed.tier).toBeUndefined();
    expect(presentation.payload).not.toContain('ada@example.com');
  });

  it('makes two presentations of the same credential unlinkable', async () => {
    const presenter = new BbsPresenter();
    const verifier = new BbsVerifier(issuer.publicKey);

    // One credential, no batch issuance.
    const credential = await issuer.issue(CLAIMS);

    const reqA = request({ verifierId: 'https://a.example', audience: 'https://a.example' });
    const reqB = request({ verifierId: 'https://b.example', audience: 'https://b.example' });
    const presentationA = await presenter.present(reqA, credential);
    const presentationB = await presenter.present(reqB, credential);

    // Both verify and disclose the same claim...
    expect((await verifier.verify(presentationA, reqA)).category_sports).toBe('climbing');
    expect((await verifier.verify(presentationB, reqB)).category_sports).toBe('climbing');

    // ...but the proofs are re-randomized: they share no correlatable bytes.
    const proofA = JSON.parse(presentationA.payload).proof as string;
    const proofB = JSON.parse(presentationB.payload).proof as string;
    expect(proofA).not.toEqual(proofB);

    // Even presenting twice to the same verifier with the same nonce stays distinct.
    const fixed = request();
    const first = await presenter.present(fixed, credential);
    const second = await presenter.present(fixed, credential);
    expect(JSON.parse(first.payload).proof).not.toEqual(JSON.parse(second.payload).proof);
  });

  it('rejects a presentation with the wrong nonce', async () => {
    const presenter = new BbsPresenter();
    const verifier = new BbsVerifier(issuer.publicKey);

    const credential = await issuer.issue(CLAIMS);
    const bound = request();
    const presentation = await presenter.present(bound, credential);

    await expect(verifier.verify(presentation, { ...bound, nonce: randomUUID() })).rejects.toThrow(
      VerificationError,
    );
  });

  it('rejects a presentation aimed at another audience', async () => {
    const presenter = new BbsPresenter();
    const verifier = new BbsVerifier(issuer.publicKey);

    const credential = await issuer.issue(CLAIMS);
    const req = request();
    const presentation = await presenter.present(req, credential);

    await expect(
      verifier.verify(presentation, { ...req, audience: 'https://attacker.example' }),
    ).rejects.toThrow(VerificationError);
  });

  it('rejects a proof verified against the wrong issuer key', async () => {
    const presenter = new BbsPresenter();
    const otherIssuer = await BbsIssuer.create();
    const verifier = new BbsVerifier(otherIssuer.publicKey);

    const credential = await issuer.issue(CLAIMS);
    const req = request();
    const presentation = await presenter.present(req, credential);

    await expect(verifier.verify(presentation, req)).rejects.toThrow(VerificationError);
  });

  it('rejects an unknown or replayed nonce when a nonce store is used', async () => {
    const store = new InMemoryNonceStore();
    const presenter = new BbsPresenter();
    const verifier = new BbsVerifier(issuer.publicKey, store);
    const credential = await issuer.issue(CLAIMS);

    const good = request({ nonce: await store.issue() });
    await expect(verifier.verify(await presenter.present(good, credential), good)).resolves.toEqual(
      {
        category_sports: 'climbing',
      },
    );
    await expect(verifier.verify(await presenter.present(good, credential), good)).rejects.toThrow(
      VerificationError,
    );
  });

  it('rejects an expired credential', async () => {
    const presenter = new BbsPresenter();
    const verifier = new BbsVerifier(issuer.publicKey);

    const credential = await issuer.issue(CLAIMS, { expiresInSeconds: -10 });
    const req = request();
    const presentation = await presenter.present(req, credential);

    await expect(verifier.verify(presentation, req)).rejects.toThrow(VerificationError);
  });

  it('rejects a malformed presentation payload before touching crypto', async () => {
    const verifier = new BbsVerifier(issuer.publicKey);
    const req = request();

    await expect(verifier.verify({ format: 'bbs', payload: 'not json' }, req)).rejects.toThrow(
      MalformedInputError,
    );
    await expect(verifier.verify({ format: 'bbs', payload: '{}' }, req)).rejects.toThrow(
      MalformedInputError,
    );
  });
});
