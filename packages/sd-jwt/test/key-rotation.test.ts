import { randomUUID } from 'node:crypto';
import { keyring, type PresentationRequest, VerificationError } from '@veil/core';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  generateKeyPair,
  type KeyPair,
  SdJwtIssuer,
  SdJwtPresenter,
  SdJwtVerifier,
} from '../src/index.js';

const CLAIMS = { user_id: 'u', email: 'a@b.c', tier: 'gold', category_sports: 'climbing' };

let holder: KeyPair;
beforeAll(async () => {
  holder = await generateKeyPair();
});

function request(): PresentationRequest {
  return {
    verifierId: 'https://v.example',
    requestedClaims: ['category_sports'],
    nonce: randomUUID(),
    audience: 'https://v.example',
  };
}

describe('SD-JWT key rotation', () => {
  it('resolves the issuer key by kid', async () => {
    const oldKey = await generateKeyPair();
    const newKey = await generateKeyPair();
    const issuer = new SdJwtIssuer('https://issuer.example', newKey.privateKey, { kid: 'k2' });
    const verifier = new SdJwtVerifier(keyring({ k1: oldKey.publicKey, k2: newKey.publicKey }));

    const credential = await issuer.issue(CLAIMS, holder.publicKey);
    const req = request();
    const disclosed = await verifier.verify(
      await new SdJwtPresenter(holder.privateKey).present(req, credential),
      req,
    );
    expect(disclosed.category_sports).toBe('climbing');
  });

  it('rejects an unknown kid', async () => {
    const key = await generateKeyPair();
    const issuer = new SdJwtIssuer('https://issuer.example', key.privateKey, { kid: 'missing' });
    const verifier = new SdJwtVerifier(keyring({ known: key.publicKey }));

    const credential = await issuer.issue(CLAIMS, holder.publicKey);
    const req = request();
    const presentation = await new SdJwtPresenter(holder.privateKey).present(req, credential);
    await expect(verifier.verify(presentation, req)).rejects.toThrow(VerificationError);
  });
});
