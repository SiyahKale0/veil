# Changelog

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
