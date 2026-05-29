# Veil

Prove something true about you without revealing who you are.

Veil is a user-held trust layer: an issuer signs a credential, the holder keeps
it on their own device, and the holder can prove a single fact to a verifier
while everything else stays hidden.

This first milestone implements selective disclosure with SD-JWT-VC
([RFC 9901](https://datatracker.ietf.org/doc/html/rfc9901)). A membership
credential carries four claims; the holder discloses `category_sports` to a
verifier while `user_id`, `email` and `tier` never leave the device. Each
presentation is bound to the holder's key and to the verifier's nonce and
audience, so it cannot be replayed or reused elsewhere.

## Layout

```
packages/
  core      shared contracts: Presenter, Verifier, CredentialStore, InMemoryStore
  sd-jwt    SD-JWT-VC issuer, presenter and verifier
  demo      end-to-end command-line walkthrough
```

The scheme lives behind the `Presenter` and `Verifier` contracts so other
proof systems can be added later without changing callers.

## Try it

```bash
npm install
npm run demo      # issue -> present -> verify, start to finish
npm test          # unit + negative-path tests
npm run typecheck
```

## Status

Not production-ready. The cryptography here has not been audited; treat this as
a working reference, not a deployable wallet.

## License

Apache-2.0
