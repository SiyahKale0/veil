import {
  ConsentDeniedError,
  type ConsentManager,
  type CredentialStore,
  type Presentation,
  type PresentationRequest,
  type Presenter,
} from '@veil/core';

/** A record of one consent decision, for the user's own audit trail. */
export interface ConsentLogEntry {
  verifierId: string;
  requested: string[];
  approved: string[];
  granted: boolean;
}

/**
 * Ties a credential store to a consent step. Every presentation goes through
 * the user: nothing is disclosed without approval, and only the approved claims
 * are presented, even if the verifier asked for more.
 */
export class Wallet {
  private readonly log: ConsentLogEntry[] = [];

  constructor(
    private readonly store: CredentialStore,
    private readonly consent: ConsentManager,
  ) {}

  /**
   * Presents a stored credential to a verifier after the user consents. The
   * `presenter` carries the holder key to use for this verifier (see pairwise
   * identity). Throws {@link ConsentDeniedError} if the user declines — in which
   * case no presentation is produced and nothing leaves the wallet.
   */
  async present(
    credentialId: string,
    presenter: Presenter,
    request: PresentationRequest,
  ): Promise<Presentation> {
    const decision = await this.consent.request(request);
    const approved = decision.approved
      ? request.requestedClaims.filter((claim) => decision.approvedClaims.includes(claim))
      : [];
    const granted = decision.approved && approved.length > 0;

    this.log.push({
      verifierId: request.verifierId,
      requested: request.requestedClaims,
      approved,
      granted,
    });

    if (!granted) {
      throw new ConsentDeniedError();
    }

    const credential = await this.store.get(credentialId);
    if (!credential) {
      throw new Error(`no credential stored under "${credentialId}"`);
    }

    // Disclose only what the user approved — scope-based disclosure.
    return presenter.present({ ...request, requestedClaims: approved }, credential);
  }

  /** The consent decisions made so far, oldest first. */
  consentLog(): readonly ConsentLogEntry[] {
    return this.log;
  }
}
