import { randomUUID } from 'node:crypto';
import { InMemoryStore, type PresentationRequest } from 'veil-core';
import {
  generateKeyPair,
  type MembershipClaims,
  SdJwtIssuer,
  SdJwtPresenter,
  SdJwtVerifier,
} from 'veil-sd-jwt';

const HIDDEN_CLAIMS = ['user_id', 'email', 'tier'] as const;

async function main(): Promise<void> {
  // Each actor holds its own keys; the issuer and the holder never share secrets.
  const issuerKeys = await generateKeyPair();
  const holderKeys = await generateKeyPair();

  const issuer = new SdJwtIssuer('https://issuer.veil.dev', issuerKeys.privateKey);
  const presenter = new SdJwtPresenter(holderKeys.privateKey);
  const verifier = new SdJwtVerifier(issuerKeys.publicKey);
  const store = new InMemoryStore();

  // 1. The issuer signs a credential bound to the holder's key.
  const claims: MembershipClaims = {
    user_id: 'u_8f3a21',
    email: 'ada@example.com',
    tier: 'gold',
    category_sports: 'climbing',
  };
  const credential = await issuer.issue(claims, holderKeys.publicKey);
  await store.put('membership', credential);
  console.log('1. Credential issued and stored.');
  console.log(`   Claims signed: ${Object.keys(claims).join(', ')}\n`);

  // 2. A verifier asks only for the sports category.
  const request: PresentationRequest = {
    verifierId: 'https://gym.example',
    requestedClaims: ['category_sports'],
    nonce: randomUUID(),
    audience: 'https://gym.example',
  };
  console.log('2. Verifier requests:', request.requestedClaims.join(', '), '\n');

  // 3. The holder presents, disclosing only what was asked.
  const held = await store.get('membership');
  if (!held) throw new Error('credential not found in store');
  const presentation = await presenter.present(request, held);
  console.log('3. Holder presented a proof (only the requested claim disclosed).\n');

  // 4. The verifier checks the proof and reads what was disclosed.
  const disclosed = await verifier.verify(presentation, request);
  console.log('4. Verifier accepted the proof. Disclosed claims:');
  console.log(`   category_sports = ${String(disclosed.category_sports)}\n`);

  // 5. Confirm the hidden claims never reached the verifier.
  const leaked = HIDDEN_CLAIMS.filter((claim) => claim in disclosed);
  if (leaked.length > 0) {
    throw new Error(`privacy failure: hidden claims leaked: ${leaked.join(', ')}`);
  }
  console.log('5. Hidden claims stayed hidden:', HIDDEN_CLAIMS.join(', '));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
