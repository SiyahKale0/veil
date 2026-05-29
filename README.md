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

The vault keeps credentials encrypted at rest and can sync through a server that
only ever sees ciphertext, so a credential restores on another device from the
blob plus the password. Sharing always goes through an explicit consent step,
and only the approved claims are disclosed.

## Layout

```
packages/
  core      shared contracts: Presenter, Verifier, CredentialStore, ConsentManager
  sd-jwt    SD-JWT-VC issuer, presenter, verifier, pairwise keys
  vault     encrypted-at-rest credential store and zero-knowledge sync
  consent   consent step and the wallet that enforces scope-based disclosure
  demo      end-to-end command-line walkthroughs
```

The scheme lives behind the `Presenter` and `Verifier` contracts so other
proof systems can be added later without changing callers.

## Pairwise identity and its limit

The holder shows a different key to each verifier (`PairwiseKeyManager`), so two
verifiers cannot link the user by the key binding. With SD-JWT this costs one
credential per verifier (batch issuance), and it only goes so far: the issuer's
signature and the disclosed values are still correlatable across presentations.
Unlinkability that does not need batch issuance — re-randomized proofs from a
single credential — is the job of the BBS scheme in a later phase.

## Try it

```bash
npm install
npm run demo           # issue -> present -> verify, start to finish
npm run demo:vault     # encrypt, sync, restore on another device
npm run demo:consent   # two apps, consent, scope-based disclosure, pairwise keys
npm test               # unit + negative-path tests
npm run typecheck
```

## Status

Not production-ready. The cryptography here has not been audited; treat this as
a working reference, not a deployable wallet.

## License

Apache-2.0
