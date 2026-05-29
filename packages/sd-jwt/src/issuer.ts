import { digest, ES256, generateSalt } from '@sd-jwt/crypto-nodejs';
import type { SdJwtVcPayload } from '@sd-jwt/sd-jwt-vc';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import type { DisclosureFrame } from '@sd-jwt/types';
import type { Credential } from '@veil/core';
import type { Jwk } from './keys.js';
import { DISCLOSABLE_CLAIMS, MEMBERSHIP_VCT, type MembershipClaims } from './membership.js';

/** Signs membership credentials bound to a holder's key. */
export class SdJwtIssuer {
  private readonly sdjwt: Promise<SDJwtVcInstance>;

  constructor(
    private readonly issuerId: string,
    issuerPrivateKey: Jwk,
  ) {
    this.sdjwt = (async () => {
      const signer = await ES256.getSigner(issuerPrivateKey);
      return new SDJwtVcInstance({
        signer,
        signAlg: ES256.alg,
        hasher: digest,
        hashAlg: 'sha-256',
        saltGenerator: generateSalt,
      });
    })();
  }

  /**
   * Issues a membership credential. Every claim is selectively disclosable, and
   * the credential is bound to `holderPublicKey` via the `cnf` confirmation
   * claim so only that holder can present it.
   */
  async issue(claims: MembershipClaims, holderPublicKey: Jwk): Promise<Credential> {
    const sdjwt = await this.sdjwt;
    const payload: SdJwtVcPayload = {
      iss: this.issuerId,
      iat: Math.floor(Date.now() / 1000),
      vct: MEMBERSHIP_VCT,
      cnf: { jwk: holderPublicKey },
      ...claims,
    };
    // SD-JWT-VC payloads carry an index signature, which makes DisclosureFrame
    // reject a literal `_sd` list (a typing limitation in @sd-jwt). The value
    // below is the correct runtime frame: mark every claim selectively disclosable.
    const disclosureFrame = { _sd: [...DISCLOSABLE_CLAIMS] };
    const raw = await sdjwt.issue(
      payload,
      disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>,
    );
    return { raw, type: MEMBERSHIP_VCT };
  }
}
