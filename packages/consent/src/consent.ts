import type { ConsentDecision, ConsentManager, PresentationRequest } from 'veil-core';

type Prompt = (request: PresentationRequest) => ConsentDecision | Promise<ConsentDecision>;

/** A consent manager that defers each decision to a callback (e.g. a UI prompt). */
export class CallbackConsentManager implements ConsentManager {
  constructor(private readonly prompt: Prompt) {}

  async request(request: PresentationRequest): Promise<ConsentDecision> {
    return this.prompt(request);
  }
}

/** Approves every requested claim. */
export const approveAll: ConsentManager = new CallbackConsentManager((request) => ({
  approved: true,
  approvedClaims: request.requestedClaims,
}));

/** Approves only the listed claims, ignoring anything else the verifier asked for. */
export function approveOnly(...claims: string[]): ConsentManager {
  return new CallbackConsentManager((request) => ({
    approved: true,
    approvedClaims: request.requestedClaims.filter((claim) => claims.includes(claim)),
  }));
}

/** Declines every request. */
export const denyAll: ConsentManager = new CallbackConsentManager(() => ({
  approved: false,
  approvedClaims: [],
}));
