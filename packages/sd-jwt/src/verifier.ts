import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import type { KbVerifier } from '@sd-jwt/types';
import {
  assertWithinSize,
  type DisclosedClaims,
  type KeyResolver,
  MAX_PAYLOAD_BYTES,
  type NonceStore,
  type Presentation,
  type PresentationRequest,
  VerificationError,
  type Verifier,
} from 'veil-core';
import type { Jwk } from './keys.js';
import { digest, ES256 } from './webcrypto.js';

/** Reads the `kid` from the issuer JWT header of an SD-JWT compact string. */
function readKid(compact: string): string | undefined {
  try {
    const headerB64 = compact.split('~')[0].split('.')[0];
    const header = JSON.parse(atob(headerB64.replace(/-/g, '+').replace(/_/g, '/'))) as {
      kid?: string;
    };
    return typeof header.kid === 'string' ? header.kid : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Verifies SD-JWT-VC presentations: the issuer signature (resolved by `kid` when
 * a resolver is given, so issuer keys can rotate), the holder's key-binding
 * (from the credential's `cnf` claim), the nonce and audience from the request,
 * the credential expiry, and the presence of the requested claims.
 *
 * Returns only what the holder disclosed; hidden claims never appear here.
 */
export class SdJwtVerifier implements Verifier {
  private readonly resolveKey: KeyResolver<Jwk>;
  private readonly kbVerifier: KbVerifier;

  constructor(
    issuerKey: Jwk | KeyResolver<Jwk>,
    private readonly nonceStore?: NonceStore,
  ) {
    this.resolveKey = typeof issuerKey === 'function' ? issuerKey : () => issuerKey;
    this.kbVerifier = async (data, sig, payload) => {
      const jwk = (payload?.cnf as { jwk?: Jwk } | undefined)?.jwk;
      if (!jwk) {
        throw new VerificationError('credential has no holder binding (cnf.jwk)');
      }
      const verifyKb = await ES256.getVerifier(jwk);
      return verifyKb(data, sig);
    };
  }

  async verify(presentation: Presentation, request: PresentationRequest): Promise<DisclosedClaims> {
    if (presentation.format !== 'sd-jwt-vc') {
      throw new VerificationError(`unsupported presentation format: ${presentation.format}`);
    }
    assertWithinSize(presentation.payload, MAX_PAYLOAD_BYTES, 'presentation.payload');

    if (this.nonceStore && !(await this.nonceStore.consume(request.nonce))) {
      throw new VerificationError('nonce is stale, unknown, or already used');
    }

    const issuerKey = await this.resolveKey(readKid(presentation.payload));
    if (!issuerKey) {
      throw new VerificationError('unknown issuer key');
    }
    const sdjwt = new SDJwtVcInstance({
      verifier: await ES256.getVerifier(issuerKey),
      kbVerifier: this.kbVerifier,
      hasher: digest,
      hashAlg: 'sha-256',
    });

    const result = await sdjwt
      .verify(presentation.payload, {
        requiredClaimKeys: request.requestedClaims,
        keyBindingNonce: request.nonce,
      })
      .catch((error: unknown) => {
        throw new VerificationError(`presentation rejected: ${(error as Error).message}`);
      });

    if (!result.kb) {
      throw new VerificationError('presentation is missing the required key binding');
    }
    if (result.kb.payload.aud !== request.audience) {
      throw new VerificationError('key-binding audience does not match the request');
    }

    const { exp } = result.payload as { exp?: number };
    if (typeof exp === 'number' && exp < Math.floor(Date.now() / 1000)) {
      throw new VerificationError('credential has expired');
    }

    return result.payload as DisclosedClaims;
  }
}
