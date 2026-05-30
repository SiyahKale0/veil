/**
 * Resolves an issuer's public key by its key id (`kid`), so a verifier can
 * accept credentials signed by a current or recently-rotated key.
 *
 * `kid` is `undefined` when a credential carries no key id. Returning `null`
 * means "unknown key" and the verification is rejected. The key type `K` is
 * scheme-specific (a JWK for SD-JWT, a base64 public key for BBS/ZK).
 */
export type KeyResolver<K> = (kid: string | undefined) => K | null | Promise<K | null>;

/** Builds a {@link KeyResolver} from a fixed key map. */
export function keyring<K>(keys: Record<string, K>): KeyResolver<K> {
  return (kid) => (kid !== undefined ? (keys[kid] ?? null) : null);
}
