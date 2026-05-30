# veil-core

Shared contracts for [Veil](https://github.com/SiyahKale0/veil) — a privacy-first,
user-held trust layer. Prove something true about you without revealing who you are.

`veil-core` has no crypto of its own; it defines the seams every scheme plugs into:

- `Presenter`, `Verifier`, `Credential`, `PresentationRequest`, `DisclosedClaims`
- `CredentialStore` (+ `InMemoryStore`)
- `ConsentManager`, `ConsentDecision`
- `CredentialSchema` of named, typed claims (`validateClaims`, `claimNames`)
- `NonceStore` (+ `InMemoryNonceStore`) for single-use, time-limited nonces
- `KeyResolver` / `keyring` for issuer key rotation
- A typed error hierarchy (`VeilError`, `VerificationError`, `MalformedInputError`, …)
  and small validation guards for untrusted input

Isomorphic: runs in Node and the browser (Web Crypto + standard globals only).

```bash
npm install veil-core
```

## Status

Not production-ready. The cryptography in the Veil packages has not been
independently audited. See the [repository](https://github.com/SiyahKale0/veil)
and its `SECURITY.md`.

## License

Apache-2.0
