# veil-zk

Zero-knowledge predicate proofs for [Veil](https://github.com/SiyahKale0/veil):
prove `age >= 18` or `balance >= 100` over a numeric claim **without revealing the
value**. The verifier learns only true or false.

A composite proof binds a BBS proof-of-knowledge to a Bulletproofs++ range proof
(transparent, no trusted setup), so the bound is checked against the signed claim.
Built on `@docknetwork/crypto-wasm-ts`; runs in Node and, with a WASM-aware
bundler, in the browser.

```bash
npm install veil-zk veil-core
```

```ts
import { ZkAgeIssuer, ZkAgeProver, ZkAgeVerifier } from 'veil-zk';

const issuer = await ZkAgeIssuer.create();
const credential = await issuer.issue({ user_id: 'u1', age: 25 });
const ctx = { nonce: crypto.randomUUID(), audience: 'https://bar.example' };

const proof = await new ZkAgeProver().proveAgeAtLeast(credential, 18, ctx);
const ok = await new ZkAgeVerifier(issuer.publicKey).verifyAgeAtLeast(proof, 18, ctx); // true
```

For other claims use the generic `ZkPredicateIssuer` / `ZkPredicateProver` /
`ZkPredicateVerifier`.

## Status

Not production-ready; the cryptography has not been independently audited, and
ciphersuite conformance/interop is unverified. See the
[repository](https://github.com/SiyahKale0/veil) and its `SECURITY.md`.

## License

Apache-2.0
