import {
  asString,
  asStringRecord,
  type CredentialSchema,
  type DisclosedClaims,
  MAX_PAYLOAD_BYTES,
  type NonceStore,
  type Presentation,
  type PresentationRequest,
  parseJsonObject,
  VerificationError,
  type Verifier,
} from '@veil/core';
import { challenge, ensureReady, fromB64, getParams, lib, utf8 } from './internal.js';
import { membershipSchema } from './membership.js';

/**
 * Verifies BBS presentations against the issuer's public key, checking the proof
 * and the nonce/audience binding, and returns only the disclosed claims.
 */
export class BbsVerifier implements Verifier {
  private readonly publicKey: InstanceType<typeof lib.BBSPublicKey>;

  constructor(
    issuerPublicKey: string,
    private readonly nonceStore?: NonceStore,
    private readonly schema: CredentialSchema = membershipSchema,
  ) {
    this.publicKey = new lib.BBSPublicKey(fromB64(issuerPublicKey));
  }

  async verify(presentation: Presentation, request: PresentationRequest): Promise<DisclosedClaims> {
    if (presentation.format !== 'bbs') {
      throw new VerificationError(`unsupported presentation format: ${presentation.format}`);
    }

    await ensureReady();
    const params = getParams(this.schema);
    const names = this.schema.map((definition) => definition.name);

    // Validate the untrusted payload before touching any crypto.
    const raw = parseJsonObject(presentation.payload, MAX_PAYLOAD_BYTES, 'presentation.payload');
    const proofB64 = asString(raw.proof, 'presentation.proof');
    const revealed = asStringRecord(raw.revealed, 'presentation.revealed');

    const revealedMsgs = new Map<number, Uint8Array>();
    for (const [name, value] of Object.entries(revealed)) {
      const index = names.indexOf(name);
      if (index < 0) {
        throw new VerificationError(`unknown claim: ${name}`);
      }
      revealedMsgs.set(index, utf8(value));
    }

    for (const claim of request.requestedClaims) {
      if (!(claim in revealed)) {
        throw new VerificationError(`requested claim was not disclosed: ${claim}`);
      }
    }

    if (this.nonceStore && !(await this.nonceStore.consume(request.nonce))) {
      throw new VerificationError('nonce is stale, unknown, or already used');
    }

    let verified = false;
    try {
      const proof = new lib.BBSPoKSigProof(fromB64(proofB64));
      const contribution = proof.challengeContribution(params, true, revealedMsgs);
      const result = proof.verify(
        challenge(contribution, request),
        this.publicKey,
        params,
        true,
        revealedMsgs,
      );
      verified = result.verified;
    } catch {
      throw new VerificationError('presentation rejected: malformed proof');
    }
    if (!verified) {
      throw new VerificationError('presentation rejected: invalid proof');
    }

    return { ...revealed };
  }
}
