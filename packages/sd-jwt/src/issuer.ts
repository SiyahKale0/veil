import { digest, ES256, generateSalt } from '@sd-jwt/crypto-nodejs';
import type { SdJwtVcPayload } from '@sd-jwt/sd-jwt-vc';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import type { DisclosureFrame } from '@sd-jwt/types';
import {
  type ClaimValues,
  type Credential,
  type CredentialSchema,
  claimNames,
  validateClaims,
} from '@veil/core';
import type { Jwk } from './keys.js';
import { MEMBERSHIP_VCT, membershipSchema } from './membership.js';

/** Default credential lifetime: one year. */
const DEFAULT_VALIDITY_SECONDS = 365 * 24 * 60 * 60;

/** Options for a single issuance. */
export interface IssueOptions {
  /** Seconds until the credential expires (`exp`). Defaults to one year. */
  expiresInSeconds?: number;
}

/** Options for an issuer instance. */
export interface SdJwtIssuerOptions {
  /** The credential schema. Defaults to the membership schema. */
  schema?: CredentialSchema;
  /** The credential type (`vct`). Defaults to the membership vct. */
  vct?: string;
}

/** Signs credentials bound to a holder's key. Schema-driven; membership by default. */
export class SdJwtIssuer {
  private readonly sdjwt: Promise<SDJwtVcInstance>;
  private readonly schema: CredentialSchema;
  private readonly vct: string;

  constructor(
    private readonly issuerId: string,
    issuerPrivateKey: Jwk,
    options: SdJwtIssuerOptions = {},
  ) {
    this.schema = options.schema ?? membershipSchema;
    this.vct = options.vct ?? MEMBERSHIP_VCT;
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
   * Issues a credential whose claims match this issuer's schema. Every claim is
   * selectively disclosable, and the credential is bound to `holderPublicKey` via
   * the `cnf` confirmation claim so only that holder can present it.
   */
  async issue(
    claims: ClaimValues,
    holderPublicKey: Jwk,
    options: IssueOptions = {},
  ): Promise<Credential> {
    validateClaims(this.schema, claims);
    const sdjwt = await this.sdjwt;
    const issuedAt = Math.floor(Date.now() / 1000);
    const payload: SdJwtVcPayload = {
      iss: this.issuerId,
      iat: issuedAt,
      exp: issuedAt + (options.expiresInSeconds ?? DEFAULT_VALIDITY_SECONDS),
      vct: this.vct,
      cnf: { jwk: holderPublicKey },
      ...claims,
    };
    // SD-JWT-VC payloads carry an index signature, which makes DisclosureFrame
    // reject a literal `_sd` list (a typing limitation in @sd-jwt). The value
    // below is the correct runtime frame: mark every claim selectively disclosable.
    const disclosureFrame = { _sd: claimNames(this.schema) };
    const raw = await sdjwt.issue(
      payload,
      disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>,
    );
    return { raw, type: this.vct };
  }
}
