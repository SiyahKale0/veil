import {
  asIntInRange,
  asString,
  asStringRecord,
  type CredentialSchema,
  type DisclosedClaims,
  type KeyResolver,
  MAX_PAYLOAD_BYTES,
  type NonceStore,
  type Presentation,
  type PresentationRequest,
  parseJsonObject,
  VerificationError,
  type Verifier,
} from 'veil-core';
import { challenge, ensureReady, expIndex, fromB64, getLib, getParams, utf8 } from './internal.js';
import { membershipSchema } from './membership.js';

/**
 * Verifies BBS presentations against the issuer's public key (resolved by `kid`
 * when a resolver is given, so issuer keys can rotate), checking the proof and
 * the nonce/audience binding, and returns only the disclosed claims.
 */
export class BbsVerifier implements Verifier {
  private readonly resolveKey: KeyResolver<string>;

  constructor(
    issuerKey: string | KeyResolver<string>,
    private readonly nonceStore?: NonceStore,
    private readonly schema: CredentialSchema = membershipSchema,
  ) {
    this.resolveKey = typeof issuerKey === 'function' ? issuerKey : () => issuerKey;
  }

  async verify(presentation: Presentation, request: PresentationRequest): Promise<DisclosedClaims> {
    if (presentation.format !== 'bbs') {
      throw new VerificationError(`unsupported presentation format: ${presentation.format}`);
    }

    await ensureReady();
    const lib = getLib();
    const params = getParams(this.schema);
    const names = this.schema.map((definition) => definition.name);

    // Validate the untrusted payload before touching any crypto.
    const raw = parseJsonObject(presentation.payload, MAX_PAYLOAD_BYTES, 'presentation.payload');
    const proofB64 = asString(raw.proof, 'presentation.proof');
    const revealed = asStringRecord(raw.revealed, 'presentation.revealed');
    const exp = asIntInRange(raw.exp, 0, Number.MAX_SAFE_INTEGER, 'presentation.exp');
    const kid = typeof raw.kid === 'string' ? raw.kid : undefined;

    const issuerKey = await this.resolveKey(kid);
    if (!issuerKey) {
      throw new VerificationError('unknown issuer key');
    }
    const publicKey = new lib.BBSPublicKey(fromB64(issuerKey));

    const revealedMsgs = new Map<number, Uint8Array>();
    for (const [name, value] of Object.entries(revealed)) {
      const index = names.indexOf(name);
      if (index < 0) {
        throw new VerificationError(`unknown claim: ${name}`);
      }
      revealedMsgs.set(index, utf8(value));
    }
    // The expiry is bound to the proof at its reserved index, so it cannot be forged.
    revealedMsgs.set(expIndex(this.schema), utf8(String(exp)));

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
        publicKey,
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
    if (exp < Math.floor(Date.now() / 1000)) {
      throw new VerificationError('credential has expired');
    }

    return { ...revealed };
  }
}
