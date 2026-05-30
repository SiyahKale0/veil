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
  bbs       BBS scheme: selective disclosure with unlinkable presentations
  zk        zero-knowledge predicate proofs (e.g. age >= 18) over a BBS credential
  demo      end-to-end command-line walkthroughs
```

The scheme lives behind the `Presenter` and `Verifier` contracts so other
proof systems can be added later without changing callers.

## Pairwise identity and its limit

The holder shows a different key to each verifier (`PairwiseKeyManager`), so two
verifiers cannot link the user by the key binding. With SD-JWT this costs one
credential per verifier (batch issuance), and it only goes so far: the issuer's
signature and the disclosed values are still correlatable across presentations.

The `bbs` package removes that cost: a single credential yields a freshly
re-randomized proof on every presentation, so two presentations are unlinkable
without issuing multiple credentials. Both schemes sit behind the same
`Presenter` / `Verifier` contracts, so callers do not change.

## Predicate proofs

The `zk` package proves a statement about a claim without disclosing it — for
example "age >= 18" over a privately held age. A composite proof binds a BBS
proof-of-knowledge to a Bulletproofs++ range proof (transparent, no trusted
setup) so the bound is checked against the signed age, and the verifier learns
only true or false. The earlier phase also envisioned a browser WASM-SIMD
benchmark; that needs a browser harness and is not part of this Node build.

## Try it

```bash
npm install
npm run demo           # issue -> present -> verify, start to finish
npm run demo:vault     # encrypt, sync, restore on another device
npm run demo:consent   # two apps, consent, scope-based disclosure, pairwise keys
npm run demo:bbs       # one credential, two unlinkable presentations
npm run demo:zk        # prove age >= 18 without revealing the age
npm test               # unit + negative-path tests (Node)
npm run test:browser   # same flows in headless Chromium (needs: npx playwright install chromium)
npm run typecheck
```

## Browser support

All packages run in both Node and the browser. This is verified by a headless
Chromium smoke test (`npm run test:browser`) that runs the SD-JWT, vault, BBS and
ZK flows in a real browser.

| Package | Node | Browser |
| --- | --- | --- |
| `core`, `sd-jwt`, `consent`, `vault`, `bbs`, `zk` | yes | yes |

Every package works in the browser with no setup from the caller. `core`,
`sd-jwt`, `consent` and `vault` use only the Web Crypto API (`globalThis.crypto`),
standard globals, and (for the vault) Argon2id via the self-contained hash-wasm
build.

`bbs` and `zk` load `crypto-wasm-ts` with a plain dynamic `import()`. That
library's WASM loader references Node's `Buffer`, so before loading it the
packages install a guarded `Buffer` shim (only when one is missing — a no-op in
Node). The caller does not need a bundler polyfill plugin.

## Performance

Median prove/verify times in headless Chromium (`npm run bench:browser`), on the
machine used for development:

| Scheme | prove | verify |
| --- | --- | --- |
| SD-JWT | ~0.3 ms | ~0.4 ms |
| BBS | ~17 ms | ~20 ms |
| ZK age predicate | ~480 ms | ~200 ms |

These are the same order of magnitude as Node. The WASM uses whatever the runtime
provides (e.g. SIMD), so a SIMD on/off comparison isn't exposed; mobile browsers
will be slower (typically a few times), which mainly affects the ZK predicate.

## Status

Not production-ready. The cryptography here has not been audited; treat this as
a working reference, not a deployable wallet.

### Cryptographic basis and conformance

- **SD-JWT** follows RFC 9901 via `@sd-jwt` (OpenWallet Foundation); ES256 / SHA-256
  come from the Web Crypto API.
- **Vault** uses Argon2id (hash-wasm) for key derivation and AES-256-GCM (Web
  Crypto) for authenticated encryption.
- **BBS / ZK** use `@docknetwork/crypto-wasm-ts` (BLS12-381): a BBS
  proof-of-knowledge with selective disclosure, and a Bulletproofs++ range proof
  (transparent, no trusted setup).

Before production, two things are open and need real work:

1. **An independent security audit** of the whole stack.
2. **Ciphersuite conformance / interop.** The BBS and ZK schemes follow the
   library's own BBS construction; byte-level conformance to a specific published
   ciphersuite (IETF `draft-irtf-cfrg-bbs-signatures`, W3C `vc-di-bbs`) and
   interop with other BBS implementations have **not** been verified. That
   requires running the official test vectors and pinning a named ciphersuite.

See [SECURITY.md](SECURITY.md) for the full threat model, the security-review
checklist, and how to report a vulnerability.

## Building

`npm run build` compiles every package to `dist/` with type declarations. The
packages are workspace-internal source packages today; the `dist` output is what
a published npm release would ship, so wiring `exports` to `dist` is the one
remaining step before publishing to a registry.

## License

Apache-2.0 — see [LICENSE](LICENSE).
