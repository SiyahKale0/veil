import type {
  Credential,
  CredentialSchema,
  Presentation,
  PresentationRequest,
  Presenter,
} from 'veil-core';
import {
  challenge,
  ensureReady,
  expIndex,
  fromB64,
  getLib,
  getParams,
  toB64,
  utf8,
} from './internal.js';
import { membershipSchema } from './membership.js';

interface BbsCredential {
  fields: string[];
  values: string[];
  exp: number;
  signature: string;
  kid?: string;
}

/**
 * Builds a BBS proof that discloses only the requested claims. Each call
 * produces a freshly re-randomized proof, so two presentations of the same
 * credential cannot be linked to each other.
 */
export class BbsPresenter implements Presenter {
  constructor(private readonly schema: CredentialSchema = membershipSchema) {}

  async present(request: PresentationRequest, credential: Credential): Promise<Presentation> {
    await ensureReady();
    const params = getParams(this.schema);
    const parsed = JSON.parse(credential.raw) as BbsCredential;
    // Messages are the claim values plus the reserved expiry slot at the end.
    const messages = [...parsed.values, String(parsed.exp)].map(utf8);
    const lib = getLib();
    const signature = new lib.BBSSignature(fromB64(parsed.signature));

    const names = this.schema.map((definition) => definition.name);
    const claimIndices = request.requestedClaims.map((name) => {
      const index = names.indexOf(name);
      if (index < 0) {
        throw new Error(`unknown claim: ${name}`);
      }
      return index;
    });
    // Always reveal the expiry so the verifier can enforce it.
    const revealedIndices = [...claimIndices, expIndex(this.schema)];
    const revealedSet = new Set(revealedIndices);
    const revealedMsgs = new Map(revealedIndices.map((index) => [index, messages[index]]));

    const protocol = lib.BBSPoKSignatureProtocol.initialize(
      messages,
      signature,
      params,
      true,
      undefined,
      revealedSet,
    );
    const contribution = protocol.challengeContribution(params, true, revealedMsgs);
    const proof = protocol.generateProof(challenge(contribution, request));

    const revealed: Record<string, string> = {};
    for (const index of claimIndices) {
      revealed[names[index]] = parsed.values[index];
    }

    const payload = JSON.stringify({
      proof: toB64(proof.bytes),
      revealed,
      exp: parsed.exp,
      kid: parsed.kid,
    });
    return { format: 'bbs', payload };
  }
}
