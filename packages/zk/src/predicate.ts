import {
  asIntInRange,
  asString,
  type ClaimValues,
  type Credential,
  type CredentialSchema,
  type KeyResolver,
  MAX_PAYLOAD_BYTES,
  type NonceStore,
  type Presentation,
  parseJsonObject,
  VerificationError,
  validateClaims,
} from '@veil/core';
import {
  DEFAULT_UPPER_BOUND,
  DEFAULT_VALIDITY_SECONDS,
  encodeClaims,
  encodeNumber,
  ensureReady,
  expIndex,
  fromB64,
  getBppParams,
  getLib,
  getSigParams,
  type Lib,
  toB64,
  utf8,
} from './internal.js';

/** Binds a proof to a verifier's nonce and audience, blocking replay and redirection. */
export interface ProofContext {
  nonce: string;
  audience: string;
}

/** Options for a single issuance. */
export interface IssueOptions {
  /** Seconds until the credential expires. Defaults to one year. */
  expiresInSeconds?: number;
}

interface ZkCredential {
  messages: string[];
  exp: number;
  signature: string;
  kid?: string;
}

function numericClaimIndex(schema: CredentialSchema, claimName: string): number {
  const index = schema.findIndex((definition) => definition.name === claimName);
  if (index < 0) {
    throw new Error(`unknown claim: ${claimName}`);
  }
  if (schema[index].type !== 'number') {
    throw new Error(`claim "${claimName}" is not numeric and cannot be range-proven`);
  }
  return index;
}

function equalityMeta(
  lib: Lib,
  signatureStatement: number,
  boundStatement: number,
  claimIndex: number,
) {
  const eq = new lib.WitnessEqualityMetaStatement();
  eq.addWitnessRef(signatureStatement, claimIndex);
  eq.addWitnessRef(boundStatement, 0);
  const metaStatements = new lib.MetaStatements();
  metaStatements.addWitnessEquality(eq);
  return metaStatements;
}

/** Issues a BBS credential whose numeric claims can be range-proven. */
export class ZkPredicateIssuer {
  private constructor(
    private readonly secretKey: InstanceType<Lib['BBSSecretKey']>,
    private readonly publicKeyB64: string,
    private readonly schema: CredentialSchema,
    private readonly type: string,
    private readonly kid?: string,
  ) {}

  get publicKey(): string {
    return this.publicKeyB64;
  }

  static async create(
    schema: CredentialSchema,
    type: string,
    kid?: string,
  ): Promise<ZkPredicateIssuer> {
    await ensureReady();
    const keypair = getLib().BBSKeypair.generate(getSigParams(schema));
    return new ZkPredicateIssuer(
      keypair.secretKey,
      toB64(keypair.publicKey.bytes),
      schema,
      type,
      kid,
    );
  }

  async issue(values: ClaimValues, options: IssueOptions = {}): Promise<Credential> {
    validateClaims(this.schema, values);
    await ensureReady();
    const exp =
      Math.floor(Date.now() / 1000) + (options.expiresInSeconds ?? DEFAULT_VALIDITY_SECONDS);
    const messages = [...encodeClaims(this.schema, values), encodeNumber(exp)];
    const signature = getLib().BBSSignature.generate(
      messages,
      this.secretKey,
      getSigParams(this.schema),
      false,
    );
    const raw = JSON.stringify({
      messages: messages.map(toB64),
      exp,
      signature: toB64(signature.bytes),
      kid: this.kid,
    });
    return { raw, type: this.type };
  }
}

/** Proves that a numeric claim is at least `min`, without revealing the claim. */
export class ZkPredicateProver {
  constructor(private readonly schema: CredentialSchema) {}

  async proveAtLeast(
    credential: Credential,
    claimName: string,
    min: number,
    context: ProofContext,
  ): Promise<Presentation> {
    await ensureReady();
    const lib = getLib();
    const claimIndex = numericClaimIndex(this.schema, claimName);
    const parsed = JSON.parse(credential.raw) as ZkCredential;
    const messages = parsed.messages.map(fromB64);
    const signature = new lib.BBSSignature(fromB64(parsed.signature));
    const exp = expIndex(this.schema);

    // Reveal the expiry (so the verifier can enforce it); keep everything else hidden.
    const revealed = new Map([[exp, messages[exp]]]);
    const statements = new lib.Statements();
    const sigStatement = statements.add(
      lib.Statement.bbsSignatureProverConstantTime(getSigParams(this.schema), revealed, false),
    );
    const boundStatement = statements.add(
      lib.Statement.boundCheckBppFromCompressedParams(min, DEFAULT_UPPER_BOUND, getBppParams()),
    );
    const proofSpec = new lib.ProofSpec(
      statements,
      equalityMeta(lib, sigStatement, boundStatement, claimIndex),
      [],
      utf8(context.audience),
    );

    const unrevealed = new Map(
      messages
        .map((message, index): [number, Uint8Array] => [index, message])
        .filter(([index]) => index !== exp),
    );
    const witnesses = new lib.Witnesses();
    witnesses.add(lib.Witness.bbsSignatureConstantTime(signature, unrevealed, false));
    witnesses.add(lib.Witness.boundCheckBpp(messages[claimIndex]));

    const proof = lib.CompositeProof.generate(proofSpec, witnesses, utf8(context.nonce));
    return {
      format: 'zk',
      payload: JSON.stringify({ proof: toB64(proof.bytes), exp: parsed.exp, kid: parsed.kid }),
    };
  }
}

/** Verifies an at-least predicate over a numeric claim against the issuer's key. */
export class ZkPredicateVerifier {
  private readonly resolveKey: KeyResolver<string>;

  constructor(
    private readonly schema: CredentialSchema,
    issuerKey: string | KeyResolver<string>,
    private readonly nonceStore?: NonceStore,
  ) {
    this.resolveKey = typeof issuerKey === 'function' ? issuerKey : () => issuerKey;
  }

  async verifyAtLeast(
    presentation: Presentation,
    claimName: string,
    min: number,
    context: ProofContext,
  ): Promise<boolean> {
    if (presentation.format !== 'zk') {
      throw new VerificationError(`unsupported presentation format: ${presentation.format}`);
    }
    await ensureReady();
    const lib = getLib();
    const claimIndex = numericClaimIndex(this.schema, claimName);
    const raw = parseJsonObject(presentation.payload, MAX_PAYLOAD_BYTES, 'presentation.payload');
    const proofB64 = asString(raw.proof, 'presentation.proof');
    const exp = asIntInRange(raw.exp, 0, Number.MAX_SAFE_INTEGER, 'presentation.exp');
    const kid = typeof raw.kid === 'string' ? raw.kid : undefined;

    if (this.nonceStore && !(await this.nonceStore.consume(context.nonce))) {
      throw new VerificationError('nonce is stale, unknown, or already used');
    }

    const issuerKey = await this.resolveKey(kid);
    if (!issuerKey) {
      throw new VerificationError('unknown issuer key');
    }
    const publicKey = new lib.BBSPublicKey(fromB64(issuerKey));
    const revealed = new Map([[expIndex(this.schema), encodeNumber(exp)]]);
    const statements = new lib.Statements();
    const sigStatement = statements.add(
      lib.Statement.bbsSignatureVerifierConstantTime(
        getSigParams(this.schema),
        publicKey,
        revealed,
        false,
      ),
    );
    const boundStatement = statements.add(
      lib.Statement.boundCheckBppFromCompressedParams(min, DEFAULT_UPPER_BOUND, getBppParams()),
    );
    const proofSpec = new lib.ProofSpec(
      statements,
      equalityMeta(lib, sigStatement, boundStatement, claimIndex),
      [],
      utf8(context.audience),
    );

    let verified = false;
    try {
      const proof = new lib.CompositeProof(fromB64(proofB64));
      verified = proof.verify(proofSpec, utf8(context.nonce)).verified;
    } catch {
      throw new VerificationError('predicate proof rejected: malformed proof');
    }
    if (!verified) {
      throw new VerificationError('predicate proof rejected: invalid proof');
    }
    if (exp < Math.floor(Date.now() / 1000)) {
      throw new VerificationError('credential has expired');
    }
    return true;
  }
}
