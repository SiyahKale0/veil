import { BbsIssuer, BbsPresenter, BbsVerifier } from '@veil/bbs';
import type { PresentationRequest } from '@veil/core';
import { generateKeyPair, SdJwtIssuer, SdJwtPresenter, SdJwtVerifier } from '@veil/sd-jwt';
import { ZkAgeIssuer, ZkAgeProver, ZkAgeVerifier } from '@veil/zk';
import { describe, expect, it } from 'vitest';

const CLAIMS = { user_id: 'u', email: 'a@b.c', tier: 'gold', category_sports: 'climbing' };
const RUNS = 5;

function request(): PresentationRequest {
  return {
    verifierId: 'https://v.example',
    requestedClaims: ['category_sports'],
    nonce: crypto.randomUUID(),
    audience: 'https://v.example',
  };
}

async function median(run: () => Promise<void>, runs: number): Promise<number> {
  const samples: number[] = [];
  for (let i = 0; i < runs; i += 1) {
    const start = performance.now();
    await run();
    samples.push(performance.now() - start);
  }
  samples.sort((a, b) => a - b);
  return samples[Math.floor(samples.length / 2)];
}

describe('browser performance (median ms)', () => {
  it('SD-JWT prove / verify', async () => {
    const issuerKeys = await generateKeyPair();
    const holderKeys = await generateKeyPair();
    const issuer = new SdJwtIssuer('https://issuer.example', issuerKeys.privateKey);
    const presenter = new SdJwtPresenter(holderKeys.privateKey);
    const verifier = new SdJwtVerifier(issuerKeys.publicKey);
    const credential = await issuer.issue(CLAIMS, holderKeys.publicKey);

    const prove = await median(async () => {
      await presenter.present(request(), credential);
    }, RUNS);
    const req = request();
    const presentation = await presenter.present(req, credential);
    const verify = await median(async () => {
      await verifier.verify(presentation, req);
    }, RUNS);

    console.log(`SD-JWT  prove=${prove.toFixed(1)}ms  verify=${verify.toFixed(1)}ms`);
    expect(prove).toBeGreaterThan(0);
  });

  it('BBS prove / verify', async () => {
    const issuer = await BbsIssuer.create();
    const presenter = new BbsPresenter();
    const verifier = new BbsVerifier(issuer.publicKey);
    const credential = await issuer.issue(CLAIMS);

    const prove = await median(async () => {
      await presenter.present(request(), credential);
    }, RUNS);
    const req = request();
    const presentation = await presenter.present(req, credential);
    const verify = await median(async () => {
      await verifier.verify(presentation, req);
    }, RUNS);

    console.log(`BBS     prove=${prove.toFixed(1)}ms  verify=${verify.toFixed(1)}ms`);
    expect(prove).toBeGreaterThan(0);
  });

  it('ZK age predicate prove / verify', async () => {
    const issuer = await ZkAgeIssuer.create();
    const prover = new ZkAgeProver();
    const verifier = new ZkAgeVerifier(issuer.publicKey);
    const credential = await issuer.issue({ user_id: 'u', age: 25 });
    const ctx = () => ({ nonce: crypto.randomUUID(), audience: 'https://v.example' });

    const prove = await median(async () => {
      await prover.proveAgeAtLeast(credential, 18, ctx());
    }, RUNS);
    const c = ctx();
    const presentation = await prover.proveAgeAtLeast(credential, 18, c);
    const verify = await median(async () => {
      await verifier.verifyAgeAtLeast(presentation, 18, c);
    }, RUNS);

    console.log(`ZK      prove=${prove.toFixed(1)}ms  verify=${verify.toFixed(1)}ms`);
    expect(verify).toBeGreaterThan(0);
  });
});
