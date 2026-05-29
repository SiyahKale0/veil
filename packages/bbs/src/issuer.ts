import {
  type ClaimValues,
  type Credential,
  type CredentialSchema,
  claimNames,
  validateClaims,
} from '@veil/core';
import { ensureReady, getParams, lib, toB64, utf8 } from './internal.js';
import { BBS_MEMBERSHIP_TYPE, membershipSchema } from './membership.js';

/** Signs credentials under BBS. Schema-driven; membership by default. */
export class BbsIssuer {
  private constructor(
    private readonly secretKey: InstanceType<typeof lib.BBSSecretKey>,
    private readonly publicKeyB64: string,
    private readonly schema: CredentialSchema,
    private readonly type: string,
  ) {}

  /** The issuer's public key, base64url-encoded, to hand to verifiers. */
  get publicKey(): string {
    return this.publicKeyB64;
  }

  static async create(
    schema: CredentialSchema = membershipSchema,
    type: string = BBS_MEMBERSHIP_TYPE,
  ): Promise<BbsIssuer> {
    await ensureReady();
    const keypair = lib.BBSKeypair.generate(getParams(schema));
    return new BbsIssuer(keypair.secretKey, toB64(keypair.publicKey.bytes), schema, type);
  }

  /**
   * Issues a BBS credential over the schema's claims. A single credential is
   * enough for unlinkable presentations — no batch issuance needed.
   */
  async issue(values: ClaimValues): Promise<Credential> {
    validateClaims(this.schema, values);
    await ensureReady();
    const ordered = this.schema.map((definition) => String(values[definition.name]));
    const messages = ordered.map(utf8);
    const signature = lib.BBSSignature.generate(
      messages,
      this.secretKey,
      getParams(this.schema),
      true,
    );
    const raw = JSON.stringify({
      fields: claimNames(this.schema),
      values: ordered,
      signature: toB64(signature.bytes),
    });
    return { raw, type: this.type };
  }
}
