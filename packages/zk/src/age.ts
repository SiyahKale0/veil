import {
  asString,
  type Credential,
  MAX_PAYLOAD_BYTES,
  type NonceStore,
  type Presentation,
  parseJsonObject,
  VerificationError,
} from '@veil/core';
import {
  AGE_INDEX,
  encodeMessages,
  ensureReady,
  fromB64,
  getBppParams,
  getLib,
  getSigParams,
  type Lib,
  MAX_AGE,
  toB64,
  utf8,
} from './internal.js';

/** The credential type (vct) for the BBS age credential used in range proofs. */
export const ZK_AGE_TYPE = 'https://veil.dev/credentials/age-bbs/v1';

export interface AgeClaims {
  user_id: string;
  age: number;
}

/** Binds a proof to a verifier's nonce and audience, blocking replay and redirection. */
export interface ProofContext {
  nonce: string;
  audience: string;
}

interface AgeCredential {
  messages: string[];
  signature: string;
}

/** Issues a BBS credential whose age field can be range-proven. */
export class ZkAgeIssuer {
  private constructor(
    private readonly secretKey: InstanceType<Lib['BBSSecretKey']>,
    private readonly publicKeyB64: string,
  ) {}

  get publicKey(): string {
    return this.publicKeyB64;
  }

  static async create(): Promise<ZkAgeIssuer> {
    await ensureReady();
    const keypair = getLib().BBSKeypair.generate(getSigParams());
    return new ZkAgeIssuer(keypair.secretKey, toB64(keypair.publicKey.bytes));
  }

  async issue(claims: AgeClaims): Promise<Credential> {
    await ensureReady();
    const messages = encodeMessages(claims.user_id, claims.age);
    const signature = getLib().BBSSignature.generate(
      messages,
      this.secretKey,
      getSigParams(),
      false,
    );
    const raw = JSON.stringify({
      messages: messages.map(toB64),
      signature: toB64(signature.bytes),
    });
    return { raw, type: ZK_AGE_TYPE };
  }
}

function ageEqualityMetaStatements(signatureStatement: number, boundStatement: number) {
  const lib = getLib();
  const eq = new lib.WitnessEqualityMetaStatement();
  eq.addWitnessRef(signatureStatement, AGE_INDEX);
  eq.addWitnessRef(boundStatement, 0);
  const metaStatements = new lib.MetaStatements();
  metaStatements.addWitnessEquality(eq);
  return metaStatements;
}

/** Proves the holder's age is at least `minAge` without revealing the age. */
export class ZkAgeProver {
  async proveAgeAtLeast(
    credential: Credential,
    minAge: number,
    context: ProofContext,
  ): Promise<Presentation> {
    await ensureReady();
    const lib = getLib();
    const parsed = JSON.parse(credential.raw) as AgeCredential;
    const messages = parsed.messages.map(fromB64);
    const signature = new lib.BBSSignature(fromB64(parsed.signature));

    const statements = new lib.Statements();
    const sigStatement = statements.add(
      lib.Statement.bbsSignatureProverConstantTime(getSigParams(), new Map(), false),
    );
    const boundStatement = statements.add(
      lib.Statement.boundCheckBppFromCompressedParams(minAge, MAX_AGE, getBppParams()),
    );

    const metaStatements = ageEqualityMetaStatements(sigStatement, boundStatement);
    const proofSpec = new lib.ProofSpec(statements, metaStatements, [], utf8(context.audience));

    const unrevealed = new Map(messages.map((message, index) => [index, message]));
    const witnesses = new lib.Witnesses();
    witnesses.add(lib.Witness.bbsSignatureConstantTime(signature, unrevealed, false));
    witnesses.add(lib.Witness.boundCheckBpp(messages[AGE_INDEX]));

    const proof = lib.CompositeProof.generate(proofSpec, witnesses, utf8(context.nonce));
    return { format: 'zk', payload: JSON.stringify({ proof: toB64(proof.bytes) }) };
  }
}

/** Verifies an age-at-least proof against the issuer's public key. */
export class ZkAgeVerifier {
  constructor(
    private readonly issuerPublicKey: string,
    private readonly nonceStore?: NonceStore,
  ) {}

  /**
   * Verifies that the proof shows age >= `minAge`. The verifier chooses `minAge`
   * itself; nothing in the proof can widen the bound. Throws on any failure.
   */
  async verifyAgeAtLeast(
    presentation: Presentation,
    minAge: number,
    context: ProofContext,
  ): Promise<boolean> {
    if (presentation.format !== 'zk') {
      throw new VerificationError(`unsupported presentation format: ${presentation.format}`);
    }
    await ensureReady();
    const lib = getLib();
    const raw = parseJsonObject(presentation.payload, MAX_PAYLOAD_BYTES, 'presentation.payload');
    const proofB64 = asString(raw.proof, 'presentation.proof');

    if (this.nonceStore && !(await this.nonceStore.consume(context.nonce))) {
      throw new VerificationError('nonce is stale, unknown, or already used');
    }

    const publicKey = new lib.BBSPublicKey(fromB64(this.issuerPublicKey));
    const statements = new lib.Statements();
    const sigStatement = statements.add(
      lib.Statement.bbsSignatureVerifierConstantTime(getSigParams(), publicKey, new Map(), false),
    );
    const boundStatement = statements.add(
      lib.Statement.boundCheckBppFromCompressedParams(minAge, MAX_AGE, getBppParams()),
    );

    const metaStatements = ageEqualityMetaStatements(sigStatement, boundStatement);
    const proofSpec = new lib.ProofSpec(statements, metaStatements, [], utf8(context.audience));

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
    return true;
  }
}
