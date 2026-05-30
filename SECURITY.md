# Security

## Status

Veil is a working reference, **not production-ready**. The cryptography has not
been independently audited. Do not use it to protect real credentials or secrets
until the open items under "Before production" are addressed.

## Reporting a vulnerability

Please report suspected vulnerabilities privately rather than opening a public
issue. Use GitHub's "Report a vulnerability" (Security advisories) on the
repository. Include a description, affected packages, and a reproduction if
possible. Please allow time for a fix before any public disclosure.

## Design principles

- No hand-rolled cryptography. Primitives come from audited libraries and the
  platform: Web Crypto (ES256, AES-256-GCM, SHA-256, randomness), Argon2id via
  hash-wasm, BBS/Bulletproofs++ via `@docknetwork/crypto-wasm-ts`.
- Data minimization: the holder discloses only what is asked and approved.
- Keys stay on the holder's device; the sync server only ever holds an opaque,
  encrypted blob.
- Secrets are never logged. Error messages are generic and do not echo inputs.

## Threat model

| Threat | Mitigation |
| --- | --- |
| Sync-server compromise | Zero-knowledge vault: the server holds only ciphertext; the password and keys never leave the device. |
| Malicious verifier (over-asking) | Explicit consent step; only approved claims are disclosed (scope-based disclosure). |
| Verifier collusion / linkability | SD-JWT pairwise keys (per verifier); BBS re-randomized proofs are unlinkable across presentations without batch issuance. |
| Device compromise | Vault encrypted at rest (Argon2id-derived key, AES-256-GCM); per-credential DEKs so one leaked key exposes one credential. |
| Replay / stale presentation | Proofs bound to the verifier's nonce and audience; single-use, time-limited nonces (`NonceStore`); credential expiry enforced. |
| Crafted untrusted input | Presentations and vault blobs are size- and shape-validated before any crypto; KDF parameters are bounded to prevent resource exhaustion. |
| Issuer key rotation | Credentials carry a `kid`; verifiers resolve the issuer key via a key ring, so old and new keys both verify and unknown keys are rejected. |

## Security-review checklist

Before trusting a deployment, confirm:

- [ ] An independent cryptography/security audit has been completed.
- [ ] BBS/ZK ciphersuite conformance and interop verified against official test
      vectors; a named ciphersuite is pinned.
- [ ] Argon2id parameters tuned and benchmarked for the target devices.
- [ ] Dependencies pinned and `npm audit` clean; supply chain reviewed.
- [ ] Verifiers use a `NonceStore` and enforce credential expiry.
- [ ] Issuer keys are managed with rotation (`kid`) and stored in an HSM/KMS.
- [ ] Holder-side key and vault storage hardened for the target platform.
- [ ] Logging reviewed to ensure no secrets or full credentials are emitted.

## Before production

1. **Independent security audit** of the whole stack.
2. **Ciphersuite conformance / interop.** The BBS and ZK schemes follow the
   library's own BBS construction on BLS12-381. Byte-level conformance to a
   published ciphersuite (IETF `draft-irtf-cfrg-bbs-signatures`, W3C `vc-di-bbs`)
   and interop with other BBS implementations have not been verified.

These are also tracked in the README.
