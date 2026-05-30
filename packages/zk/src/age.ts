import type {
  Credential,
  CredentialSchema,
  KeyResolver,
  NonceStore,
  Presentation,
} from 'veil-core';
import {
  type IssueOptions,
  type ProofContext,
  ZkPredicateIssuer,
  ZkPredicateProver,
  ZkPredicateVerifier,
} from './predicate.js';

/** The credential type (vct) for the BBS age credential used in range proofs. */
export const ZK_AGE_TYPE = 'https://veil.dev/credentials/age-bbs/v1';

export type AgeClaims = {
  user_id: string;
  age: number;
};

/** The age credential's schema: a hashed id and a range-provable age. */
const ageSchema = [
  { name: 'user_id', type: 'string' },
  { name: 'age', type: 'number' },
] as const satisfies CredentialSchema;

/**
 * Age-specific convenience over the generic predicate API: issue, prove and
 * verify "age >= N" without revealing the age. For other credential shapes or
 * claims, use {@link ZkPredicateIssuer} / {@link ZkPredicateProver} /
 * {@link ZkPredicateVerifier} directly.
 */
export class ZkAgeIssuer {
  private constructor(private readonly inner: ZkPredicateIssuer) {}

  get publicKey(): string {
    return this.inner.publicKey;
  }

  static async create(kid?: string): Promise<ZkAgeIssuer> {
    return new ZkAgeIssuer(await ZkPredicateIssuer.create(ageSchema, ZK_AGE_TYPE, kid));
  }

  issue(claims: AgeClaims, options?: IssueOptions): Promise<Credential> {
    return this.inner.issue(claims, options);
  }
}

export class ZkAgeProver {
  private readonly inner = new ZkPredicateProver(ageSchema);

  proveAgeAtLeast(
    credential: Credential,
    minAge: number,
    context: ProofContext,
  ): Promise<Presentation> {
    return this.inner.proveAtLeast(credential, 'age', minAge, context);
  }
}

export class ZkAgeVerifier {
  private readonly inner: ZkPredicateVerifier;

  constructor(issuerKey: string | KeyResolver<string>, nonceStore?: NonceStore) {
    this.inner = new ZkPredicateVerifier(ageSchema, issuerKey, nonceStore);
  }

  verifyAgeAtLeast(
    presentation: Presentation,
    minAge: number,
    context: ProofContext,
  ): Promise<boolean> {
    return this.inner.verifyAtLeast(presentation, 'age', minAge, context);
  }
}
