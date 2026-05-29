/** The credential type (vct) used by the membership credential in this phase. */
export const MEMBERSHIP_VCT = 'https://veil.dev/credentials/membership/v1';

/**
 * A membership credential's claims.
 *
 * All four are issued as selectively disclosable, so the holder decides at
 * presentation time which to reveal. The intended use: reveal `category_sports`
 * while `user_id`, `email` and `tier` stay hidden.
 */
export interface MembershipClaims {
  user_id: string;
  email: string;
  tier: string;
  category_sports: string;
}

/** Claim keys made selectively disclosable when the credential is issued. */
export const DISCLOSABLE_CLAIMS = [
  'user_id',
  'email',
  'tier',
  'category_sports',
] as const satisfies ReadonlyArray<keyof MembershipClaims>;
