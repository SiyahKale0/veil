# Changelog

## Unreleased — hardening toward production

- Tooling: Biome lint and format, a GitHub Actions CI workflow, exact-pinned
  dependencies, per-package builds with declarations, and zero audit advisories.
- Trust boundaries: a typed error hierarchy with generic messages, and
  size- and shape-validation of untrusted presentations and vault blobs before
  any crypto runs. KDF parameters read from a blob are bounded so a crafted blob
  cannot exhaust memory during unlock.
- Freshness and lifecycle: single-use, time-limited nonces (`InMemoryNonceStore`)
  can be wired into any verifier to reject unknown, expired or replayed nonces;
  SD-JWT credentials now carry and enforce an expiry.

## 0.5.0

Zero-knowledge age predicate.

- `@veil/zk` — `ZkAgeIssuer`, `ZkAgeProver` and `ZkAgeVerifier` prove a statement
  like "age >= 18" without revealing the age. A composite proof ties a BBS
  signature proof-of-knowledge to a Bulletproofs++ range proof through a
  witness-equality constraint, so the bound is checked against the signed age.
- Bulletproofs++ is transparent — no trusted setup. Proofs are bound to the
  verifier's nonce and audience.
- The verifier learns only true/false and chooses the threshold itself; the
  proof cannot be stretched past the real age.
- `npm run demo:zk` proves age >= 18 for a private age of 25 and prints timings
  (~0.6 s prove, ~0.2 s verify here).
- Tests cover the boundary, a threshold the age does not meet, wrong nonce /
  audience / issuer key, and that the same age proves >= 21 but not >= 26.

Scope note: the original phase also called for a browser WASM-SIMD
before/after benchmark. That needs a browser harness and is out of scope for
this Node/CLI build; only Node prove/verify timings are reported here.

## 0.4.0

BBS selective disclosure with multi-presentation unlinkability.

- `@veil/bbs` — `BbsIssuer`, `BbsPresenter` and `BbsVerifier` on
  `@docknetwork/crypto-wasm-ts` (Rust→WASM, BLS12-381). They implement the same
  `Presenter` / `Verifier` contracts as the SD-JWT scheme.
- A single credential produces re-randomized proofs, so two presentations cannot
  be linked — no batch issuance, unlike the SD-JWT pairwise approach.
- Proofs are bound to the verifier's nonce and audience to block replay.
- `npm run demo:bbs` issues one credential, presents it to two verifiers, shows
  the proofs share no bytes, and prints prove/verify timings (~20 ms each here).
- Tests cover disclosure, hidden claims, the unlinkability (collusion) check,
  wrong nonce / audience / issuer key, and a contract test that runs the same
  flow through both the SD-JWT and BBS schemes.

Alignment note: the library implements the BBS proof-of-knowledge scheme with
selective disclosure on BLS12-381, in line with the IRTF CFRG BBS work. Exact
byte-level conformance to a specific draft ciphersuite has not been verified and
remains open before any production use.

## 0.3.0

Cross-app presentation with consent and pairwise identity.

- `@veil/core` — `ConsentManager` and `ConsentDecision` contracts plus
  `ConsentDeniedError`.
- `@veil/consent` — `Wallet` runs every presentation through a consent step and
  discloses only the approved claims, even when the verifier asks for more; it
  keeps an audit log of decisions. Ships `approveAll`, `approveOnly(...)`,
  `denyAll`, and `CallbackConsentManager`.
- `@veil/sd-jwt` — `PairwiseKeyManager` hands out a distinct holder key per
  verifier, so verifiers cannot link the user by the key binding.
- `npm run demo:consent` walks two apps: the gym gets the one claim it asked
  for; the insurer asks for two but the user approves one; a declined request
  produces nothing; and the two apps see different holder keys.
- Tests cover scoped disclosure, consent denial producing no presentation, the
  consent log, and pairwise bindings.
- README documents the SD-JWT linkability limit that motivates BBS next.

## 0.2.0

Encrypted vault and zero-knowledge sync.

- `@veil/vault` — `EncryptedVaultStore`, a `CredentialStore` that keeps every
  credential encrypted at rest. Envelope encryption: a per-credential random DEK
  wrapped by a KEK derived from the password with Argon2id; data sealed with
  XChaCha20-Poly1305 (libsodium).
- `export()` produces an opaque blob with no plaintext, key, or password; a
  credential can be restored on another device from the blob plus the password.
- `InMemoryVaultSync` stands in for the sync server and only ever holds the
  opaque blob.
- Wrong passwords are rejected at unlock via a KEK-sealed check token.
- `npm run demo:vault` shows the full path: encrypt, sync, reject a wrong
  password, restore on another device, then present and verify the credential.
- Tests cover store round-trip, opaque export, cross-device restore, wrong
  password, and a distinct DEK per credential.

## 0.1.0

First milestone: SD-JWT-VC selective disclosure.

- `@veil/core` — `Presenter`, `Verifier` and `CredentialStore` contracts plus an
  in-memory store.
- `@veil/sd-jwt` — issuer, presenter and verifier built on SD-JWT-VC (RFC 9901)
  with ES256 signatures and holder key binding.
- A membership credential issues four selectively disclosable claims; the holder
  reveals only `category_sports`, and `user_id` / `email` / `tier` stay hidden.
- Presentations are bound to the verifier's nonce and audience to block replay.
- `npm run demo` walks the full issue → present → verify flow.
- Tests cover the happy path, the store round-trip, and rejection of tampered
  proofs, wrong nonces, mismatched audiences, forced disclosure, and the wrong
  issuer key.
