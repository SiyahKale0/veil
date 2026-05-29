/**
 * A credential schema: the ordered, named, typed claims a credential carries.
 * Issuer, holder and verifier agree on a schema, which is what lets the library
 * carry any credential type rather than a single hard-coded one.
 */
import { MalformedInputError } from './errors.js';

export type ClaimType = 'string' | 'number';

export interface ClaimDefinition {
  readonly name: string;
  /** `number` claims must be non-negative integers (so they can be range-proven). */
  readonly type: ClaimType;
}

export type CredentialSchema = readonly ClaimDefinition[];

/** A set of claim values to be issued, keyed by claim name. */
export type ClaimValues = Record<string, string | number>;

/** The ordered claim names of a schema. */
export function claimNames(schema: CredentialSchema): string[] {
  return schema.map((definition) => definition.name);
}

/** Checks that `values` provides every schema claim with the right type. */
export function validateClaims(schema: CredentialSchema, values: ClaimValues): void {
  for (const definition of schema) {
    const value = values[definition.name];
    if (definition.type === 'string') {
      if (typeof value !== 'string') {
        throw new MalformedInputError(`claim "${definition.name}" must be a string`);
      }
    } else if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
      throw new MalformedInputError(`claim "${definition.name}" must be a non-negative integer`);
    }
  }
}
