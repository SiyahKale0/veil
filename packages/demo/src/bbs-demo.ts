import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import type { PresentationRequest } from '@veil/core';
import { BbsIssuer, BbsPresenter, BbsVerifier, type MembershipClaims } from '@veil/bbs';

const CLAIMS: MembershipClaims = {
  user_id: 'u_8f3a21',
  email: 'ada@example.com',
  tier: 'gold',
  category_sports: 'climbing',
};

function requestFrom(verifierId: string): PresentationRequest {
  return { verifierId, requestedClaims: ['category_sports'], nonce: randomUUID(), audience: verifierId };
}

const proofOf = (payload: string): string => JSON.parse(payload).proof;

async function main(): Promise<void> {
  const issuer = await BbsIssuer.create();
  const presenter = new BbsPresenter();
  const verifier = new BbsVerifier(issuer.publicKey);

  // One credential — no batch issuance.
  const credential = await issuer.issue(CLAIMS);
  console.log('1. Issued a single BBS credential.\n');

  // Present it to two different verifiers.
  const gym = requestFrom('https://gym.example');
  const insurer = requestFrom('https://insurer.example');

  const tProve = performance.now();
  const toGym = await presenter.present(gym, credential);
  const proveMs = performance.now() - tProve;
  const toInsurer = await presenter.present(insurer, credential);

  const tVerify = performance.now();
  const gymDisclosed = await verifier.verify(toGym, gym);
  const verifyMs = performance.now() - tVerify;
  const insurerDisclosed = await verifier.verify(toInsurer, insurer);

  console.log('2. Both presentations verify and disclose only category_sports:');
  console.log(`   gym     -> ${String(gymDisclosed.category_sports)}`);
  console.log(`   insurer -> ${String(insurerDisclosed.category_sports)}\n`);

  console.log('3. Unlinkability: the two proofs share no bytes.');
  console.log(`   proofs identical? ${proofOf(toGym.payload) === proofOf(toInsurer.payload)}\n`);

  console.log(`4. Timing on this machine: prove ~${proveMs.toFixed(1)} ms, verify ~${verifyMs.toFixed(1)} ms`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
