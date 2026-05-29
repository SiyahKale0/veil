import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { ZkAgeIssuer, ZkAgeProver, ZkAgeVerifier, type ProofContext } from '@veil/zk';

function context(): ProofContext {
  return { nonce: randomUUID(), audience: 'https://bar.example' };
}

async function main(): Promise<void> {
  const issuer = await ZkAgeIssuer.create();
  const prover = new ZkAgeProver();
  const verifier = new ZkAgeVerifier(issuer.publicKey);

  // The holder gets a credential stating their age. They never show it.
  const credential = await issuer.issue({ user_id: 'u_8f3a21', age: 25 });
  console.log('1. Issued an age credential (age = 25, kept private).\n');

  // A bar asks: are you at least 18? The holder proves it without revealing 25.
  const ctx = context();
  const tProve = performance.now();
  const presentation = await prover.proveAgeAtLeast(credential, 18, ctx);
  const proveMs = performance.now() - tProve;

  const tVerify = performance.now();
  const ok = await verifier.verifyAgeAtLeast(presentation, 18, ctx);
  const verifyMs = performance.now() - tVerify;

  console.log('2. Holder proved "age >= 18" without disclosing the age.');
  console.log(`   verifier result: ${ok}  (it learns only true/false)\n`);

  // The same age satisfies a lower threshold but not one above it.
  const passes21 = await verifier
    .verifyAgeAtLeast(await prover.proveAgeAtLeast(credential, 21, ctx), 21, ctx)
    .catch(() => false);
  let passes26 = false;
  try {
    await prover.proveAgeAtLeast(credential, 26, context());
    passes26 = true;
  } catch {
    passes26 = false;
  }
  console.log('3. The proof is a real predicate, not a disclosure:');
  console.log(`   age >= 21 ? ${passes21}`);
  console.log(`   age >= 26 ? ${passes26}\n`);

  console.log(`4. Timing on this machine: prove ~${proveMs.toFixed(0)} ms, verify ~${verifyMs.toFixed(0)} ms`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
