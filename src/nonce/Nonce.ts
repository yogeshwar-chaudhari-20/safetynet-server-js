import {
  encrypt,
  verify as cryptoVerify,
} from "../wrappers/crypto.lib.wrapper";

/**
 * Nonce class for creating and verifying nonce values.
 * A nonce (number used once) is a unique value generated for security purposes.
 */
export class Nonce {
  private _data: Record<string, unknown> | string;
  private _secret: string;

  constructor(data: Record<string, unknown>, secret: string) {
    this._data = data;
    this._secret = secret;
  }

  /**
   * Creates a new nonce based on the instance's data and secret.
   * @returns A string representing the encrypted nonce.
   */
  create(): string {
    const encodedData = Buffer.from(
      JSON.stringify(this._data),
      "base64"
    ).toString();

    return encrypt(JSON.stringify(encodedData), this._secret!);
  }

  /**
   * Verifies a given nonce against the instance's data and secret.
   * @param generatedNonce The nonce to verify.
   * @returns A boolean indicating whether the nonce is valid.
   * @throws Error if the instance's data or secret is null.
   */
  verify(generatedNonce: string): boolean {
    if (this._data === null) {
      throw new Error("Nonce is can not be verified with null data.");
    }

    if (this._secret === null) {
      throw new Error(
        "Require secret to regenerate the nonce for verification."
      );
    }
    const encodedExpectedData = Buffer.from(
      JSON.stringify(this._data),
      "base64"
    ).toString();

    return cryptoVerify(generatedNonce, this._secret, encodedExpectedData);
  }
}
