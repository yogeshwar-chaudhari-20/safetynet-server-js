import { encrypt } from "../wrappers/crypto.lib.wrapper";

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

    return encrypt(JSON.stringify(encodedData), this._secret);
  }
}
