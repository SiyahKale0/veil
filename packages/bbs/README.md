# veil-bbs

BBS selective disclosure for [Veil](https://github.com/SiyahKale0/veil), with
**unlinkable** presentations: a single credential produces a freshly
re-randomized proof every time, so two presentations cannot be linked — no batch
issuance needed. Same `Presenter` / `Verifier` contracts as the SD-JWT scheme.

Built on `@docknetwork/crypto-wasm-ts` (BLS12-381). Runs in Node and, with a
WASM-aware bundler, in the browser (it self-installs a `Buffer` shim).

```bash
npm install veil-bbs veil-core
```

```ts
import { BbsIssuer, BbsPresenter, BbsVerifier } from 'veil-bbs';

const issuer = await BbsIssuer.create();
const credential = await issuer.issue({
  user_id: 'u1', email: 'ada@example.com', tier: 'gold', category_sports: 'climbing',
});
const presentation = await new BbsPresenter().present(request, credential);
const disclosed = await new BbsVerifier(issuer.publicKey).verify(presentation, request);
```

Schema-driven, with signed credential expiry and issuer key rotation.

## Status

Not production-ready; the cryptography has not been independently audited, and
ciphersuite conformance/interop is unverified. See the
[repository](https://github.com/SiyahKale0/veil) and its `SECURITY.md`.

## License

Apache-2.0
