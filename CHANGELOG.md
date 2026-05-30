# Changelog

## 0.6.1

- Each published package now ships its own README and a copy of the LICENSE, so
  the npm page documents the package and its terms.
- Packages publish under the unscoped `veil-` prefix (`veil-core`, `veil-sd-jwt`,
  `veil-vault`, `veil-consent`, `veil-bbs`, `veil-zk`) since the `@veil` org was
  unavailable. The project is still Veil.

## 0.6.0 — hardening toward production

- Persistence: `veil-vault` ships a `BlobStore` (`InMemoryBlobStore`,
  `IndexedDbBlobStore`) so a browser wallet can keep the encrypted vault blob
  across reloads. Verified against real IndexedDB in the browser tests.
- Cross-browser: the browser smoke + persistence tests now run in Chromium,
  Firefox and WebKit (Safari engine) and all pass, covering Web Crypto, the
  WASM-backed BBS/ZK flows, and IndexedDB.

- Release and assurance: added an Apache-2.0 `LICENSE` and a `SECURITY.md` with
  the threat model, a security-review checklist, vulnerability reporting, and the
  work still open before production (audit, ciphersuite conformance). `npm run
  build` emits `dist` with declarations; wiring `exports` to `dist` is the one
  remaining step before publishing to a registry.

- Crypto depth: the vault's Argon2id work factors are now tunable via
  `EncryptedVaultStore.create(password, { iterations, memoryKiB, parallelism })`,
  defaulting to the OWASP baseline. Property-based tests (fast-check) check the
  crypto invariants: the vault round-trips any credential and never opens with a
  wrong password; SD-JWT and BBS disclose exactly the requested claims and leak
  nothing else; nonces are single-use.
- Key rotation: issuers can tag credentials with a `kid`, and every verifier
  accepts either a fixed key or a `KeyResolver` (`keyring({...})`) that resolves
  the issuer key by `kid` — so an issuer can rotate keys while old and new
  credentials still verify. An unknown `kid` is rejected.
- Credential expiry everywhere: BBS and ZK credentials now carry a signed expiry
  (a reserved, always-checked slot for BBS; a revealed message for ZK), enforced
  at verification just like SD-JWT. `issue(..., { expiresInSeconds })` sets it.

- Tooling: Biome lint and format, a GitHub Actions CI workflow, exact-pinned
  dependencies, per-package builds with declarations, and zero audit advisories.
- Trust boundaries: a typed error hierarchy with generic messages, and
  size- and shape-validation of untrusted presentations and vault blobs before
  any crypto runs. KDF parameters read from a blob are bounded so a crafted blob
  cannot exhaust memory during unlock.
- Freshness and lifecycle: single-use, time-limited nonces (`InMemoryNonceStore`)
  can be wired into any verifier to reject unknown, expired or replayed nonces;
  SD-JWT credentials now carry and enforce an expiry.
- General-purpose credentials: a `CredentialSchema` of named, typed claims drives
  issuance, presentation and verification, so any credential type can be defined
  rather than the built-in membership one. SD-JWT and BBS are schema-driven
  (membership stays the default). The ZK predicate is schema-driven too:
  `ZkPredicateIssuer` / `ZkPredicateProver` / `ZkPredicateVerifier` prove
  "claim >= N" over any numeric claim (e.g. a balance threshold), with the
  age helpers (`ZkAge*`) kept as a thin convenience.
- Browser support: `core`, `sd-jwt` and `consent` are now isomorphic. SD-JWT uses
  the Web Crypto API instead of a Node-only crypto package, so the issue →
  present → verify flow runs in a browser as well as in Node. `bbs` and `zk` now
  load their WASM library with a plain dynamic `import()` instead of Node's
  `require`, so a WASM-aware bundler can run them in a browser (verified in Node
  and Vite). `vault` is now isomorphic too: it switched from libsodium to Argon2id
  via hash-wasm plus AES-256-GCM via the Web Crypto API (the AEAD alternative
  ADR-0003 already allowed), keeping memory-hard key derivation while running in
  the browser.
- Verified in a real browser: a headless-Chromium smoke test
  (`npm run test:browser`, Vitest browser mode + Playwright) runs the SD-JWT,
  vault, BBS and ZK flows. All pass with no caller setup: `bbs` and `zk` install
  a guarded `Buffer` shim themselves (a no-op in Node) so their WASM loader works
  in the browser, and their base64 helpers were made isomorphic (they previously
  used Node's `Buffer`).
- Performance: `npm run bench:browser` measures prove/verify times in headless
  Chromium (SD-JWT sub-millisecond, BBS ~20 ms, ZK predicate a few hundred ms).
  The original WASM-SIMD before/after benchmark isn't exposed (the build uses
  whatever the runtime provides), so this reports real browser timings instead.

## 0.5.0

Zero-knowledge age predicate.

- `veil-zk` — `ZkAgeIssuer`, `ZkAgeProver` and `ZkAgeVerifier` prove a statement
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

- `veil-bbs` — `BbsIssuer`, `BbsPresenter` and `BbsVerifier` on
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

- `veil-core` — `ConsentManager` and `ConsentDecision` contracts plus
  `ConsentDeniedError`.
- `veil-consent` — `Wallet` runs every presentation through a consent step and
  discloses only the approved claims, even when the verifier asks for more; it
  keeps an audit log of decisions. Ships `approveAll`, `approveOnly(...)`,
  `denyAll`, and `CallbackConsentManager`.
- `veil-sd-jwt` — `PairwiseKeyManager` hands out a distinct holder key per
  verifier, so verifiers cannot link the user by the key binding.
- `npm run demo:consent` walks two apps: the gym gets the one claim it asked
  for; the insurer asks for two but the user approves one; a declined request
  produces nothing; and the two apps see different holder keys.
- Tests cover scoped disclosure, consent denial producing no presentation, the
  consent log, and pairwise bindings.
- README documents the SD-JWT linkability limit that motivates BBS next.

## 0.2.0

Encrypted vault and zero-knowledge sync.

- `veil-vault` — `EncryptedVaultStore`, a `CredentialStore` that keeps every
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

- `veil-core` — `Presenter`, `Verifier` and `CredentialStore` contracts plus an
  in-memory store.
- `veil-sd-jwt` — issuer, presenter and verifier built on SD-JWT-VC (RFC 9901)
  with ES256 signatures and holder key binding.
- A membership credential issues four selectively disclosable claims; the holder
  reveals only `category_sports`, and `user_id` / `email` / `tier` stay hidden.
- Presentations are bound to the verifier's nonce and audience to block replay.
- `npm run demo` walks the full issue → present → verify flow.
- Tests cover the happy path, the store round-trip, and rejection of tampered
  proofs, wrong nonces, mismatched audiences, forced disclosure, and the wrong
  issuer key.
