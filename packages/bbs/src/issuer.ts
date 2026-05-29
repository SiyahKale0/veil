import type { Credential } from '@veil/core';
import { ensureReady, getParams, lib, toB64, utf8 } from './internal.js';
import { BBS_MEMBERSHIP_TYPE, FIELDS, type MembershipClaims } from './membership.js';

/** Signs membership credentials under BBS. */
export class BbsIssuer {
  private constructor(
    private readonly secretKey: InstanceType<typeof lib.BBSSecretKey>,
    private readonly publicKeyB64: string,
  ) {}

  /** The issuer's public key, base64url-encoded, to hand to verifiers. */
  get publicKey(): string {
    return this.publicKeyB64;
  }

  static async create(): Promise<BbsIssuer> {
    await ensureReady();
    const keypair = lib.BBSKeypair.generate(getParams());
    return new BbsIssuer(keypair.secretKey, toB64(keypair.publicKey.bytes));
  }

  /**
   * Issues a BBS credential over the membership claims. A single credential is
   * enough for unlinkable presentations — no batch issuance needed.
   */
  async issue(claims: MembershipClaims): Promise<Credential> {
    await ensureReady();
    const values = FIELDS.map((field) => claims[field]);
    const messages = values.map(utf8);
    const signature = lib.BBSSignature.generate(messages, this.secretKey, getParams(), true);
    const raw = JSON.stringify({ fields: FIELDS, values, signature: toB64(signature.bytes) });
    return { raw, type: BBS_MEMBERSHIP_TYPE };
  }
}
