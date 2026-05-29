import {
  type DisclosedClaims,
  type Presentation,
  type PresentationRequest,
  VerificationError,
  type Verifier,
} from '@veil/core';
import { challenge, ensureReady, fromB64, getParams, lib, utf8 } from './internal.js';
import { FIELDS } from './membership.js';

interface BbsPresentationPayload {
  proof: string;
  revealed: Record<string, string>;
}

/**
 * Verifies BBS presentations against the issuer's public key, checking the proof
 * and the nonce/audience binding, and returns only the disclosed claims.
 */
export class BbsVerifier implements Verifier {
  private readonly publicKey: InstanceType<typeof lib.BBSPublicKey>;

  constructor(issuerPublicKey: string) {
    this.publicKey = new lib.BBSPublicKey(fromB64(issuerPublicKey));
  }

  async verify(presentation: Presentation, request: PresentationRequest): Promise<DisclosedClaims> {
    if (presentation.format !== 'bbs') {
      throw new VerificationError(`unsupported presentation format: ${presentation.format}`);
    }

    await ensureReady();
    const params = getParams();
    const parsed = JSON.parse(presentation.payload) as BbsPresentationPayload;
    const proof = new lib.BBSPoKSigProof(fromB64(parsed.proof));

    const revealedMsgs = new Map<number, Uint8Array>();
    for (const [name, value] of Object.entries(parsed.revealed)) {
      const index = FIELDS.indexOf(name as (typeof FIELDS)[number]);
      if (index < 0) {
        throw new VerificationError(`unknown claim: ${name}`);
      }
      revealedMsgs.set(index, utf8(value));
    }

    for (const claim of request.requestedClaims) {
      if (!(claim in parsed.revealed)) {
        throw new VerificationError(`requested claim was not disclosed: ${claim}`);
      }
    }

    const contribution = proof.challengeContribution(params, true, revealedMsgs);
    const result = proof.verify(
      challenge(contribution, request),
      this.publicKey,
      params,
      true,
      revealedMsgs,
    );
    if (!result.verified) {
      throw new VerificationError(`presentation rejected: ${result.error ?? 'invalid proof'}`);
    }

    return { ...parsed.revealed };
  }
}
