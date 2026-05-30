import { randomUUID } from 'node:crypto';
import type { ClaimValues, CredentialSchema, PresentationRequest } from 'veil-core';
import { generateKeyPair, SdJwtIssuer, SdJwtPresenter, SdJwtVerifier } from 'veil-sd-jwt';
import { describe, expect, it } from 'vitest';
import { BbsIssuer, BbsPresenter, BbsVerifier } from '../src/index.js';

// A credential type the library does not know about: a library card.
const librarySchema: CredentialSchema = [
  { name: 'card_id', type: 'string' },
  { name: 'name', type: 'string' },
  { name: 'member_since', type: 'number' },
];

const CLAIMS: ClaimValues = { card_id: 'c-99', name: 'Ada', member_since: 2019 };

function requestFor(claims: string[]): PresentationRequest {
  return {
    verifierId: 'https://desk.example',
    requestedClaims: claims,
    nonce: randomUUID(),
    audience: 'https://desk.example',
  };
}

describe('custom credential schema', () => {
  it('issues, presents and verifies with SD-JWT', async () => {
    const issuerKeys = await generateKeyPair();
    const holderKeys = await generateKeyPair();
    const issuer = new SdJwtIssuer('https://library.example', issuerKeys.privateKey, {
      schema: librarySchema,
      vct: 'https://veil.dev/credentials/library/v1',
    });
    const presenter = new SdJwtPresenter(holderKeys.privateKey);
    const verifier = new SdJwtVerifier(issuerKeys.publicKey);

    const credential = await issuer.issue(CLAIMS, holderKeys.publicKey);
    expect(credential.type).toBe('https://veil.dev/credentials/library/v1');

    const req = requestFor(['name']);
    const disclosed = await verifier.verify(await presenter.present(req, credential), req);

    expect(disclosed.name).toBe('Ada');
    expect(disclosed.card_id).toBeUndefined();
  });

  it('issues, presents and verifies with BBS', async () => {
    const issuer = await BbsIssuer.create(
      librarySchema,
      'https://veil.dev/credentials/library-bbs/v1',
    );
    const presenter = new BbsPresenter(librarySchema);
    const verifier = new BbsVerifier(issuer.publicKey, undefined, librarySchema);

    const credential = await issuer.issue(CLAIMS);
    const req = requestFor(['name']);
    const disclosed = await verifier.verify(await presenter.present(req, credential), req);

    expect(disclosed.name).toBe('Ada');
    expect(disclosed.card_id).toBeUndefined();
  });

  it('rejects claims that do not match the schema', async () => {
    const issuerKeys = await generateKeyPair();
    const holderKeys = await generateKeyPair();
    const issuer = new SdJwtIssuer('https://library.example', issuerKeys.privateKey, {
      schema: librarySchema,
    });

    // member_since must be a non-negative integer, not a string.
    const bad = { card_id: 'c-1', name: 'Ada', member_since: 'long ago' } as unknown as ClaimValues;
    await expect(issuer.issue(bad, holderKeys.publicKey)).rejects.toThrow();
  });
});
