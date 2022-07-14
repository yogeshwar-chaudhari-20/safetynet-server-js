/**
 * Base class for extending custom errors
 */
export class BaseError extends Error {
  protected reason: string | undefined | null;
  protected solution: string | undefined | null;
  protected err: string | undefined | null;

  /**
   * @param name name of the error
   * @param message Simple string message.
   * @param reason Hint of possible reason for the exceptions.
   * @param solution Provide a link to documentation if it is configuration issue.
   * @param err Custom data or error object
   */
  constructor(
    message: string,
    reason: string | undefined | null,
    solution: string | undefined | null,
    err: any | undefined | null
  ) {
    super(message);
    this.reason = reason;
    this.solution = solution;
    this.err = err;
  }
}

export class InvalidLeafCertHostNameError extends BaseError {
  constructor(message: string, reason?: string, solution?: string, err?: any) {
    super(message, reason, solution, err);
    this.name = this.constructor.name;
  }
}

export class InvalidCertificateChainError extends BaseError {
  constructor(message: string, reason?: string, solution?: string, err?: any) {
    super(message, reason, solution, err);
    this.name = this.constructor.name;
  }
}

export class PayloadTimeStampOutOfLimitError extends BaseError {
  constructor(message: string, reason?: string, solution?: string, err?: any) {
    super(message, reason, solution, err);
    this.name = this.constructor.name;
  }
}

export class PackageNameMismatchError extends BaseError {
  constructor(message: string, reason?: string, solution?: string, err?: any) {
    super(message, reason, solution, err);
    this.name = this.constructor.name;
  }
}

export class InvalidNonceError extends BaseError {
  constructor(message: string, reason?: string, solution?: string, err?: any) {
    super(message, reason, solution, err);
    this.name = this.constructor.name;
  }
}
