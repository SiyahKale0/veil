# veil-vault

Encrypted-at-rest credential storage for [Veil](https://github.com/SiyahKale0/veil),
with zero-knowledge sync. Keys never leave the device; a sync server only ever
holds an opaque, encrypted blob.

Envelope encryption: a per-credential random DEK wrapped by a KEK derived from
the password with Argon2id (hash-wasm), data sealed with AES-256-GCM (Web Crypto).
Isomorphic — works in Node and the browser.

```bash
npm install veil-vault veil-core
```

```ts
import { EncryptedVaultStore, IndexedDbBlobStore } from 'veil-vault';

const vault = await EncryptedVaultStore.create('correct horse battery staple');
await vault.put('membership', credential);

// Persist the opaque blob (browser); restore later or on another device.
const blob = await vault.export();
const restored = await EncryptedVaultStore.unlock('correct horse battery staple', blob);
```

Includes `BlobStore` (`InMemoryBlobStore`, `IndexedDbBlobStore`) and an in-memory
`InMemoryVaultSync` stand-in for the sync server.

## Status

Not production-ready; the cryptography has not been independently audited. See the
[repository](https://github.com/SiyahKale0/veil) and its `SECURITY.md`.

## License

Apache-2.0
