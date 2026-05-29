import { generateKeyPair, type KeyPair } from './keys.js';

/**
 * Hands out a distinct holder key per verifier, so the holder shows a different
 * key binding to each one. The same verifier always gets the same key within a
 * manager instance; different verifiers never share a key.
 *
 * This is the SD-JWT route to pairwise identity, and it has a cost: each
 * verifier needs its own credential, issued against that verifier's key (batch
 * issuance). The keys are unlinkable, but the issuer's signature and the
 * disclosed values still are not — full unlinkability without batch issuance is
 * what BBS brings in a later phase.
 */
export class PairwiseKeyManager {
  private readonly keys = new Map<string, KeyPair>();

  /** Returns the holder key to use with `verifierId`, creating it on first use. */
  async keyFor(verifierId: string): Promise<KeyPair> {
    const existing = this.keys.get(verifierId);
    if (existing) {
      return existing;
    }
    const fresh = await generateKeyPair();
    this.keys.set(verifierId, fresh);
    return fresh;
  }
}
