import { ES256, digest } from '@sd-jwt/crypto-nodejs';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import type { PresentationFrame } from '@sd-jwt/types';
import type { Credential, Presentation, PresentationRequest, Presenter } from '@veil/core';
import type { Jwk } from './keys.js';

/**
 * Builds presentations from a held credential, disclosing only the claims the
 * request asks for and proving holder binding with a key-binding JWT over the
 * verifier's nonce and audience.
 */
export class SdJwtPresenter implements Presenter {
  private readonly sdjwt: Promise<SDJwtVcInstance>;

  constructor(holderPrivateKey: Jwk) {
    this.sdjwt = (async () => {
      const kbSigner = await ES256.getSigner(holderPrivateKey);
      return new SDJwtVcInstance({
        kbSigner,
        kbSignAlg: ES256.alg,
        hasher: digest,
        hashAlg: 'sha-256',
      });
    })();
  }

  async present(request: PresentationRequest, credential: Credential): Promise<Presentation> {
    const sdjwt = await this.sdjwt;
    const presentationFrame = Object.fromEntries(
      request.requestedClaims.map((claim) => [claim, true]),
    ) as PresentationFrame<Record<string, unknown>>;

    const payload = await sdjwt.present(credential.raw, presentationFrame, {
      kb: {
        payload: {
          iat: Math.floor(Date.now() / 1000),
          aud: request.audience,
          nonce: request.nonce,
        },
      },
    });

    return { format: 'sd-jwt-vc', payload };
  }
}
