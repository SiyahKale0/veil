import {
  type ClaimValues,
  type Credential,
  type CredentialSchema,
  claimNames,
  validateClaims,
} from '@veil/core';
import {
  DEFAULT_VALIDITY_SECONDS,
  ensureReady,
  getLib,
  getParams,
  type Lib,
  toB64,
  utf8,
} from './internal.js';
import { BBS_MEMBERSHIP_TYPE, membershipSchema } from './membership.js';

/** Options for a single issuance. */
export interface IssueOptions {
  /** Seconds until the credential expires. Defaults to one year. */
  expiresInSeconds?: number;
}

/** Signs credentials under BBS. Schema-driven; membership by default. */
export class BbsIssuer {
  private constructor(
    private readonly secretKey: InstanceType<Lib['BBSSecretKey']>,
    private readonly publicKeyB64: string,
    private readonly schema: CredentialSchema,
    private readonly type: string,
    private readonly kid?: string,
  ) {}

  /** The issuer's public key, base64url-encoded, to hand to verifiers. */
  get publicKey(): string {
    return this.publicKeyB64;
  }

  static async create(
    schema: CredentialSchema = membershipSchema,
    type: string = BBS_MEMBERSHIP_TYPE,
    kid?: string,
  ): Promise<BbsIssuer> {
    await ensureReady();
    const keypair = getLib().BBSKeypair.generate(getParams(schema));
    return new BbsIssuer(keypair.secretKey, toB64(keypair.publicKey.bytes), schema, type, kid);
  }

  /**
   * Issues a BBS credential over the schema's claims. A single credential is
   * enough for unlinkable presentations — no batch issuance needed.
   */
  async issue(values: ClaimValues, options: IssueOptions = {}): Promise<Credential> {
    validateClaims(this.schema, values);
    await ensureReady();
    const ordered = this.schema.map((definition) => String(values[definition.name]));
    const exp =
      Math.floor(Date.now() / 1000) + (options.expiresInSeconds ?? DEFAULT_VALIDITY_SECONDS);
    // The reserved expiry slot is signed alongside the claims (see internal.ts).
    const messages = [...ordered, String(exp)].map(utf8);
    const signature = getLib().BBSSignature.generate(
      messages,
      this.secretKey,
      getParams(this.schema),
      true,
    );
    const raw = JSON.stringify({
      fields: claimNames(this.schema),
      values: ordered,
      exp,
      signature: toB64(signature.bytes),
      kid: this.kid,
    });
    return { raw, type: this.type };
  }
}
