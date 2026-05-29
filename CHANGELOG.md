# Changelog

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
