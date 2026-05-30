import type { CredentialSchema } from 'veil-core';

/** The credential type for the BBS membership credential. */
export const BBS_MEMBERSHIP_TYPE = 'https://veil.dev/credentials/membership-bbs/v1';

/** Same membership claims as the SD-JWT credential, signed under BBS instead. */
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
