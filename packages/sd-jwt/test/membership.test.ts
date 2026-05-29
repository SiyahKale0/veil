import { randomUUID } from 'node:crypto';
import { InMemoryStore, type PresentationRequest, VerificationError } from '@veil/core';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  generateKeyPair,
  type KeyPair,
  type MembershipClaims,
  SdJwtIssuer,
  SdJwtPresenter,
  SdJwtVerifier,
} from '../src/index.js';

const ISSUER_ID = 'https://issuer.veil.dev';
const AUDIENCE = 'https://gym.example';

const CLAIMS: MembershipClaims = {
  user_id: 'u_8f3a21',
  email: 'ada@example.com',
  tier: 'gold',
  category_sports: 'climbing',
};

let issuerKeys: KeyPair;
let holderKeys: KeyPair;

beforeAll(async () => {
  issuerKeys = await generateKeyPair();
  holderKeys = await generateKeyPair();
});

function request(overrides: Partial<PresentationRequest> = {}): PresentationRequest {
  return {
    verifierId: AUDIENCE,
    requestedClaims: ['category_sports'],
    nonce: randomUUID(),
    audience: AUDIENCE,
    ...overrides,
  };
}

describe('SD-JWT membership credential', () => {
  it('discloses the requested claim end to end', async () => {
    const issuer = new SdJwtIssuer(ISSUER_ID, issuerKeys.privateKey);
    const presenter = new SdJwtPresenter(holderKeys.privateKey);
    const verifier = new SdJwtVerifier(issuerKeys.publicKey);

    const credential = await issuer.issue(CLAIMS, holderKeys.publicKey);
    const req = request();
    const presentation = await presenter.present(req, credential);
    const disclosed = await verifier.verify(presentation, req);

    expect(disclosed.category_sports).toBe('climbing');
  });

  it('round-trips through the credential store', async () => {
    const issuer = new SdJwtIssuer(ISSUER_ID, issuerKeys.privateKey);
    const presenter = new SdJwtPresenter(holderKeys.privateKey);
    const verifier = new SdJwtVerifier(issuerKeys.publicKey);
    const store = new InMemoryStore();

    const credential = await issuer.issue(CLAIMS, holderKeys.publicKey);
    await store.put('membership', credential);
    expect(await store.list()).toEqual(['membership']);

    const held = await store.get('membership');
    expect(held).not.toBeNull();
    if (!held) return;

    const req = request();
    const presentation = await presenter.present(req, held);
    const disclosed = await verifier.verify(presentation, req);
    expect(disclosed.category_sports).toBe('climbing');
  });

  it('never reveals the hidden claims to the verifier', async () => {
    const issuer = new SdJwtIssuer(ISSUER_ID, issuerKeys.privateKey);
    const presenter = new SdJwtPresenter(holderKeys.privateKey);
    const verifier = new SdJwtVerifier(issuerKeys.publicKey);

    const credential = await issuer.issue(CLAIMS, holderKeys.publicKey);
    const req = request();
    const presentation = await presenter.present(req, credential);
    const disclosed = await verifier.verify(presentation, req);

    expect(disclosed.user_id).toBeUndefined();
    expect(disclosed.email).toBeUndefined();
    expect(disclosed.tier).toBeUndefined();
    // and the raw proof must not carry the hidden values either
    expect(presentation.payload).not.toContain('ada@example.com');
    expect(presentation.payload).not.toContain('u_8f3a21');
  });

  it('rejects a presentation with the wrong nonce (replay protection)', async () => {
    const issuer = new SdJwtIssuer(ISSUER_ID, issuerKeys.privateKey);
    const presenter = new SdJwtPresenter(holderKeys.privateKey);
    const verifier = new SdJwtVerifier(issuerKeys.publicKey);

    const credential = await issuer.issue(CLAIMS, holderKeys.publicKey);
    const boundReq = request();
    const presentation = await presenter.present(boundReq, credential);

    const replayed = { ...boundReq, nonce: randomUUID() };
    await expect(verifier.verify(presentation, replayed)).rejects.toThrow(VerificationError);
  });

  it('rejects a presentation aimed at a different audience', async () => {
    const issuer = new SdJwtIssuer(ISSUER_ID, issuerKeys.privateKey);
    const presenter = new SdJwtPresenter(holderKeys.privateKey);
    const verifier = new SdJwtVerifier(issuerKeys.publicKey);

    const credential = await issuer.issue(CLAIMS, holderKeys.publicKey);
    const req = request();
    const presentation = await presenter.present(req, credential);

    const otherAudience = { ...req, audience: 'https://attacker.example' };
    await expect(verifier.verify(presentation, otherAudience)).rejects.toThrow(VerificationError);
  });

  it('cannot force disclosure of a claim the holder did not reveal', async () => {
    const issuer = new SdJwtIssuer(ISSUER_ID, issuerKeys.privateKey);
    const presenter = new SdJwtPresenter(holderKeys.privateKey);
    const verifier = new SdJwtVerifier(issuerKeys.publicKey);

    const credential = await issuer.issue(CLAIMS, holderKeys.publicKey);
    // holder only discloses category_sports...
    const presentReq = request({ requestedClaims: ['category_sports'] });
    const presentation = await presenter.present(presentReq, credential);

    // ...but the verifier demands email too.
    const demandEmail = { ...presentReq, requestedClaims: ['category_sports', 'email'] };
    await expect(verifier.verify(presentation, demandEmail)).rejects.toThrow(VerificationError);
  });

  it('rejects a credential signed by a different issuer key', async () => {
    const issuer = new SdJwtIssuer(ISSUER_ID, issuerKeys.privateKey);
    const presenter = new SdJwtPresenter(holderKeys.privateKey);
    const wrongKeys = await generateKeyPair();
    const verifier = new SdJwtVerifier(wrongKeys.publicKey);

    const credential = await issuer.issue(CLAIMS, holderKeys.publicKey);
    const req = request();
    const presentation = await presenter.present(req, credential);

    await expect(verifier.verify(presentation, req)).rejects.toThrow(VerificationError);
  });

  it('rejects a tampered proof', async () => {
    const issuer = new SdJwtIssuer(ISSUER_ID, issuerKeys.privateKey);
    const presenter = new SdJwtPresenter(holderKeys.privateKey);
    const verifier = new SdJwtVerifier(issuerKeys.publicKey);

    const credential = await issuer.issue(CLAIMS, holderKeys.publicKey);
    const req = request();
    const presentation = await presenter.present(req, credential);

    const tampered = { ...presentation, payload: `x${presentation.payload.slice(1)}` };
    await expect(verifier.verify(tampered, req)).rejects.toThrow(VerificationError);
  });
});
