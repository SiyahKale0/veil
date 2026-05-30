import type { CredentialSchema } from 'veil-core';

/** The credential type (vct) used by the membership credential. */
export const MEMBERSHIP_VCT = 'https://veil.dev/credentials/membership/v1';

/**
 * A membership credential's claims.
 *
 * All four are issued as selectively disclosable, so the holder decides at
 * presentation time which to reveal. The intended use: reveal `category_sports`
 * while `user_id`, `email` and `tier` stay hidden.
 */
export type MembershipClaims = {
  user_id: string;
  email: string;
  tier: string;
  category_sports: string;
};

/** The default schema. Any other {@link CredentialSchema} can be used instead. */
export const membershipSchema: CredentialSchema = [
  { name: 'user_id', type: 'string' },
  { name: 'email', type: 'string' },
  { name: 'tier', type: 'string' },
  { name: 'category_sports', type: 'string' },
];
