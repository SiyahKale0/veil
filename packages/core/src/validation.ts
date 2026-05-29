/**
 * Small, explicit guards for untrusted input at trust boundaries. No external
 * dependency: every check is auditable here. Each guard throws
 * {@link MalformedInputError} with a safe, field-named message and never echoes
 * the offending value (which could be attacker-controlled or sensitive).
 */
import { MalformedInputError } from './errors.js';

/** Default ceiling for a serialized proof or credential string (256 KiB). */
export const MAX_PAYLOAD_BYTES = 256 * 1024;

/** Default ceiling for a serialized vault blob (4 MiB). */
export const MAX_BLOB_BYTES = 4 * 1024 * 1024;

const utf8ByteLength = (text: string): number => new TextEncoder().encode(text).length;

/** Rejects strings larger than `maxBytes` before any further work. */
export function assertWithinSize(text: string, maxBytes: number, field: string): void {
  if (typeof text !== 'string') {
    throw new MalformedInputError(`${field} must be a string`);
  }
  if (utf8ByteLength(text) > maxBytes) {
    throw new MalformedInputError(`${field} exceeds the maximum allowed size`);
  }
}

/** Size-checked JSON parse. Returns `unknown`; narrow it with the guards below. */
export function parseJsonObject(
  text: string,
  maxBytes: number,
  field: string,
): Record<string, unknown> {
  assertWithinSize(text, maxBytes, field);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new MalformedInputError(`${field} is not valid JSON`);
  }
  return asObject(parsed, field);
}

/** Asserts a value is a plain object (not null, not an array). */
export function asObject(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new MalformedInputError(`${field} must be an object`);
  }
  return value as Record<string, unknown>;
}

export function asString(value: unknown, field: string): string {
  if (typeof value !== 'string') {
    throw new MalformedInputError(`${field} must be a string`);
  }
  return value;
}

export function asStringArray(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    throw new MalformedInputError(`${field} must be an array of strings`);
  }
  return value as string[];
}

/** Asserts a value is a finite integer within [min, max]. */
export function asIntInRange(value: unknown, min: number, max: number, field: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) {
    throw new MalformedInputError(`${field} must be an integer within the allowed range`);
  }
  return value;
}

/** Asserts every value of a record is a string and returns it typed. */
export function asStringRecord(value: unknown, field: string): Record<string, string> {
  const object = asObject(value, field);
  for (const key of Object.keys(object)) {
    asString(object[key], `${field}.${key}`);
  }
  return object as Record<string, string>;
}
