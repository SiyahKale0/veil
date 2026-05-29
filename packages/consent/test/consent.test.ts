import { randomUUID } from 'node:crypto';
import { ConsentDeniedError, InMemoryStore, type PresentationRequest } from '@veil/core';
import {
  generateKeyPair,
  type KeyPair,
  type MembershipClaims,
  PairwiseKeyManager,
  SdJwtIssuer,
  SdJwtPresenter,
  SdJwtVerifier,
} from '@veil/sd-jwt';
import { beforeAll, describe, expect, it } from 'vitest';
import { approveAll, approveOnly, denyAll, Wallet } from '../src/index.js';

const ISSUER_ID = 'https://issuer.veil.dev';
const CLAIMS: MembershipClaims = {
  user_id: 'u_8f3a21',
  email: 'ada@example.com',
  tier: 'gold',
  category_sports: 'climbing',
};

let issuerKeys: KeyPair;
let holderKeys: KeyPair;
let issuer: SdJwtIssuer;
let verifier: SdJwtVerifier;

beforeAll(async () => {
  issuerKeys = await generateKeyPair();
  holderKeys = await generateKeyPair();
  issuer = new SdJwtIssuer(ISSUER_ID, issuerKeys.privateKey);
  verifier = new SdJwtVerifier(issuerKeys.publicKey);
});

function requestFrom(verifierId: string, claims: string[]): PresentationRequest {
  return { verifierId, requestedClaims: claims, nonce: randomUUID(), audience: verifierId };
}

async function holderSetup() {
  const store = new InMemoryStore();
  await store.put('membership', await issuer.issue(CLAIMS, holderKeys.publicKey));
  return { store, presenter: new SdJwtPresenter(holderKeys.privateKey) };
}

describe('consent and scope-based disclosure', () => {
  it('presents the approved claim to the verifier', async () => {
    const { store, presenter } = await holderSetup();
    const wallet = new Wallet(store, approveAll);
    const request = requestFrom('https://gym.example', ['category_sports']);

    const presentation = await wallet.present('membership', presenter, request);
    const disclosed = await verifier.verify(presentation, request);

    expect(disclosed.category_sports).toBe('climbing');
  });

  it('discloses only the approved subset when the verifier asks for more', async () => {
    const { store, presenter } = await holderSetup();
    const wallet = new Wallet(store, approveOnly('category_sports'));
    const request = requestFrom('https://insurer.example', ['category_sports', 'tier']);

    const presentation = await wallet.present('membership', presenter, request);
    const agreed = { ...request, requestedClaims: ['category_sports'] };
    const disclosed = await verifier.verify(presentation, agreed);

    expect(disclosed.category_sports).toBe('climbing');
    expect('tier' in disclosed).toBe(false);
  });

  it('produces no presentation when consent is denied', async () => {
    const { store, presenter } = await holderSetup();
    const wallet = new Wallet(store, denyAll);
    const request = requestFrom('https://insurer.example', ['category_sports']);

    await expect(wallet.present('membership', presenter, request)).rejects.toThrow(
      ConsentDeniedError,
    );
    expect(wallet.consentLog()).toEqual([
      {
        verifierId: 'https://insurer.example',
        requested: ['category_sports'],
        approved: [],
        granted: false,
      },
    ]);
  });

  it('records every consent decision in the log', async () => {
    const { store, presenter } = await holderSetup();
    const wallet = new Wallet(store, approveOnly('category_sports'));
    const request = requestFrom('https://gym.example', ['category_sports', 'email']);

    await wallet.present('membership', presenter, request);

    expect(wallet.consentLog()).toEqual([
      {
        verifierId: 'https://gym.example',
        requested: ['category_sports', 'email'],
        approved: ['category_sports'],
        granted: true,
      },
    ]);
  });

  it('shows a different holder binding to each verifier (pairwise)', async () => {
    const pairwise = new PairwiseKeyManager();
    const gym = 'https://gym.example';
    const insurer = 'https://insurer.example';

    async function presentTo(verifierId: string) {
      const holderKey = await pairwise.keyFor(verifierId);
      const store = new InMemoryStore();
      await store.put('membership', await issuer.issue(CLAIMS, holderKey.publicKey));
      const wallet = new Wallet(store, approveAll);
      const presenter = new SdJwtPresenter(holderKey.privateKey);
      const request = requestFrom(verifierId, ['category_sports']);
      const presentation = await wallet.present('membership', presenter, request);
      return verifier.verify(presentation, request);
    }

    const toGym = await presentTo(gym);
    const toInsurer = await presentTo(insurer);

    const gymKey = (toGym.cnf as { jwk: { x: string } }).jwk.x;
    const insurerKey = (toInsurer.cnf as { jwk: { x: string } }).jwk.x;

    // both presentations verify, but the holder key differs per verifier
    expect(toGym.category_sports).toBe('climbing');
    expect(toInsurer.category_sports).toBe('climbing');
    expect(gymKey).not.toEqual(insurerKey);
  });
});
