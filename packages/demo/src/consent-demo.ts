import { randomUUID } from 'node:crypto';
import { approveAll, approveOnly, denyAll, Wallet } from 'veil-consent';
import { ConsentDeniedError, InMemoryStore, type PresentationRequest } from 'veil-core';
import {
  generateKeyPair,
  type MembershipClaims,
  PairwiseKeyManager,
  SdJwtIssuer,
  SdJwtPresenter,
  SdJwtVerifier,
} from 'veil-sd-jwt';

const CLAIMS: MembershipClaims = {
  user_id: 'u_8f3a21',
  email: 'ada@example.com',
  tier: 'gold',
  category_sports: 'climbing',
};

// Two unrelated apps the holder interacts with.
const GYM = 'https://gym.example';
const INSURER = 'https://insurer.example';

function requestFrom(verifierId: string, claims: string[]): PresentationRequest {
  return { verifierId, requestedClaims: claims, nonce: randomUUID(), audience: verifierId };
}

async function main(): Promise<void> {
  const issuerKeys = await generateKeyPair();
  const issuer = new SdJwtIssuer('https://issuer.veil.dev', issuerKeys.privateKey);
  const verifier = new SdJwtVerifier(issuerKeys.publicKey);

  // The holder uses a different key per verifier (pairwise), which means one
  // credential issued per verifier.
  const pairwise = new PairwiseKeyManager();

  async function credentialFor(verifierId: string) {
    const holderKey = await pairwise.keyFor(verifierId);
    const store = new InMemoryStore();
    await store.put('membership', await issuer.issue(CLAIMS, holderKey.publicKey));
    const presenter = new SdJwtPresenter(holderKey.privateKey);
    return { store, presenter };
  }

  // App 1: the gym asks only for the sports category; the user approves.
  {
    const { store, presenter } = await credentialFor(GYM);
    const wallet = new Wallet(store, approveAll);
    const request = requestFrom(GYM, ['category_sports']);
    const presentation = await wallet.present('membership', presenter, request);
    const disclosed = await verifier.verify(presentation, request);
    console.log('Gym requested [category_sports], user approved.');
    console.log(`   gym received: category_sports = ${String(disclosed.category_sports)}\n`);
  }

  // App 2: the insurer asks for category_sports AND tier; the user approves only
  // category_sports. The insurer gets the sports category and nothing else.
  {
    const { store, presenter } = await credentialFor(INSURER);
    const wallet = new Wallet(store, approveOnly('category_sports'));
    const request = requestFrom(INSURER, ['category_sports', 'tier']);
    const presentation = await wallet.present('membership', presenter, request);
    const agreed = { ...request, requestedClaims: ['category_sports'] };
    const disclosed = await verifier.verify(presentation, agreed);
    console.log('Insurer requested [category_sports, tier], user approved only category_sports.');
    console.log(`   insurer received: category_sports = ${String(disclosed.category_sports)}`);
    console.log(`   insurer received tier? ${'tier' in disclosed}\n`);
  }

  // App 2 again, but this time the user declines: no data flows.
  {
    const { store, presenter } = await credentialFor(INSURER);
    const wallet = new Wallet(store, denyAll);
    const request = requestFrom(INSURER, ['category_sports']);
    try {
      await wallet.present('membership', presenter, request);
    } catch (error) {
      if (error instanceof ConsentDeniedError) {
        console.log('User declined the insurer: no presentation was produced.\n');
      } else {
        throw error;
      }
    }
  }

  // Pairwise check: the key the gym sees is not the key the insurer sees.
  const gymKey = (await pairwise.keyFor(GYM)).publicKey;
  const insurerKey = (await pairwise.keyFor(INSURER)).publicKey;
  console.log('Pairwise identity: gym and insurer see different holder keys?');
  console.log(`   ${gymKey.x !== insurerKey.x}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
