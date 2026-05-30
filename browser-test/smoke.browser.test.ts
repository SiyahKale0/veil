import { BbsIssuer, BbsPresenter, BbsVerifier } from 'veil-bbs';
import type { Credential, PresentationRequest } from 'veil-core';
import { generateKeyPair, SdJwtIssuer, SdJwtPresenter, SdJwtVerifier } from 'veil-sd-jwt';
import { EncryptedVaultStore } from 'veil-vault';
import { ZkAgeIssuer, ZkAgeProver, ZkAgeVerifier } from 'veil-zk';
import { describe, expect, it } from 'vitest';

const CLAIMS = {
  user_id: 'u_1',
  email: 'ada@example.com',
  tier: 'gold',
  category_sports: 'climbing',
};

function request(): PresentationRequest {
  return {
    verifierId: 'https://verifier.example',
    requestedClaims: ['category_sports'],
    nonce: crypto.randomUUID(),
    audience: 'https://verifier.example',
  };
}

describe('browser smoke', () => {
  it('SD-JWT: issue, present and verify', async () => {
    const issuerKeys = await generateKeyPair();
    const holderKeys = await generateKeyPair();
    const issuer = new SdJwtIssuer('https://issuer.example', issuerKeys.privateKey);
    const credential = await issuer.issue(CLAIMS, holderKeys.publicKey);

    const req = request();
    const presentation = await new SdJwtPresenter(holderKeys.privateKey).present(req, credential);
    const disclosed = await new SdJwtVerifier(issuerKeys.publicKey).verify(presentation, req);

    expect(disclosed.category_sports).toBe('climbing');
    expect(disclosed.email).toBeUndefined();
  });

  it('Vault: encrypt at rest and restore', async () => {
    const credential: Credential = { raw: 'secret-token', type: 'https://veil.dev/test' };
    const device = await EncryptedVaultStore.create('correct horse battery staple');
    await device.put('membership', credential);
    const blob = await device.export();

    expect(blob).not.toContain('secret-token');

    const other = await EncryptedVaultStore.unlock('correct horse battery staple', blob);
    expect((await other.get('membership'))?.raw).toBe('secret-token');
  });

  it('BBS: present and verify (unlinkable)', async () => {
    const issuer = await BbsIssuer.create();
    const credential = await issuer.issue(CLAIMS);

    const req = request();
    const presentation = await new BbsPresenter().present(req, credential);
    const disclosed = await new BbsVerifier(issuer.publicKey).verify(presentation, req);

    expect(disclosed.category_sports).toBe('climbing');
  });

  it('ZK: prove age >= 18 without revealing it', async () => {
    const issuer = await ZkAgeIssuer.create();
    const credential = await issuer.issue({ user_id: 'u_1', age: 25 });
    const ctx = { nonce: crypto.randomUUID(), audience: 'https://verifier.example' };

    const presentation = await new ZkAgeProver().proveAgeAtLeast(credential, 18, ctx);
    const ok = await new ZkAgeVerifier(issuer.publicKey).verifyAgeAtLeast(presentation, 18, ctx);

    expect(ok).toBe(true);
  });
});
