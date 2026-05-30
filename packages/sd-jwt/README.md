# veil-sd-jwt

SD-JWT-VC selective disclosure for [Veil](https://github.com/SiyahKale0/veil).
Issue a credential, disclose only the claims a verifier asks for, and keep the
rest hidden — with holder key binding and nonce/audience binding.

Built on `@sd-jwt` (RFC 9901). Isomorphic: ES256 / SHA-256 come from the Web
Crypto API, so it runs in Node and the browser with no Node-only dependency.

```bash
npm install veil-sd-jwt veil-core
```

```ts
import { SdJwtIssuer, SdJwtPresenter, SdJwtVerifier, generateKeyPair } from 'veil-sd-jwt';

const issuerKeys = await generateKeyPair();
const holderKeys = await generateKeyPair();

const issuer = new SdJwtIssuer('https://issuer.example', issuerKeys.privateKey);
const credential = await issuer.issue(
  { user_id: 'u1', email: 'ada@example.com', tier: 'gold', category_sports: 'climbing' },
  holderKeys.publicKey,
);

const request = {
  verifierId: 'https://gym.example',
  requestedClaims: ['category_sports'],
  nonce: crypto.randomUUID(),
  audience: 'https://gym.example',
};
const presentation = await new SdJwtPresenter(holderKeys.privateKey).present(request, credential);
const disclosed = await new SdJwtVerifier(issuerKeys.publicKey).verify(presentation, request);
// disclosed.category_sports === 'climbing'; user_id / email / tier stay hidden
```

Also: schema-driven issuance, credential expiry, pairwise keys, and issuer key
rotation via a `KeyResolver`.

## Status

Not production-ready; the cryptography has not been independently audited. See the
[repository](https://github.com/SiyahKale0/veil) and its `SECURITY.md`.

## License

Apache-2.0
