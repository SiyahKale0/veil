/**
 * Error hierarchy. Messages are kept generic on purpose so verification and
 * parsing failures never leak secrets or internal structure to a caller.
 */

/** Base class for every error this library raises on purpose. */
export class VeilError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** Raised when a presentation fails verification. */
export class VerificationError extends VeilError {}

/** Raised when untrusted input is missing, malformed, oversized or out of range. */
export class MalformedInputError extends VeilError {}

/** Raised when the user declines a request; no data is presented. */
export class ConsentDeniedError extends VeilError {
  constructor(message = 'the user declined to share the requested data') {
    super(message);
  }
}
