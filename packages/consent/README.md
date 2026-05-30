# veil-consent

The consent step and wallet for [Veil](https://github.com/SiyahKale0/veil). Every
presentation goes through the user: nothing is disclosed without approval, and
only the approved claims are presented — even if the verifier asks for more.

```bash
npm install veil-consent veil-core
```

```ts
import { Wallet, approveOnly } from 'veil-consent';

const wallet = new Wallet(store, approveOnly('category_sports'));
// Verifier asks for [category_sports, tier]; the user approved only the first,
// so only category_sports is presented. A declined request produces nothing.
const presentation = await wallet.present('membership', presenter, request);
```

Ships `Wallet` (with a consent audit log), `approveAll`, `approveOnly(...)`,
`denyAll`, and `CallbackConsentManager`.

## Status

Not production-ready; the cryptography has not been independently audited. See the
[repository](https://github.com/SiyahKale0/veil) and its `SECURITY.md`.

## License

Apache-2.0
