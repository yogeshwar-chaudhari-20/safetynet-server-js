import {
  encrypt,
  verify as cryptoVerify,
} from "../wrappers/crypto.lib.wrapper";

export class Nonce {
  private _data: Record<string, unknown> | string;
  private _secret: string;

  constructor(data: Record<string, unknown>, secret: string) {
    this._data = data;
    this._secret = secret;
  }

  create(): string {
    const encodedData = Buffer.from(
      JSON.stringify(this._data),
      "base64"
    ).toString();

    return encrypt(JSON.stringify(encodedData), this._secret!);
  }

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
