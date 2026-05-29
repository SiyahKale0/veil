/** The credential type (vct) for the BBS membership credential. */
export const BBS_MEMBERSHIP_TYPE = 'https://veil.dev/credentials/membership-bbs/v1';

/** Same membership claims as the SD-JWT credential, signed under BBS instead. */
export interface MembershipClaims {
  user_id: string;
  email: string;
  tier: string;
  category_sports: string;
}

/**
 * Fixed message order. BBS signs an ordered list of messages and refers to them
 * by index, so issuer, holder and verifier must agree on this order.
 */
export const FIELDS = [
  'user_id',
  'email',
  'tier',
  'category_sports',
] as const satisfies ReadonlyArray<keyof MembershipClaims>;
