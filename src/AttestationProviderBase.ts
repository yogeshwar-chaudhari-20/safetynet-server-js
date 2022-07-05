export abstract class AttestationProviderBase {
  protected _attestationToken!: string;
  abstract getDeviceIntegrity(): boolean;

  get attestationToken() {
    return this._attestationToken;
  }

  set attestationToken(token: string) {
    this._attestationToken = token;
  }
}
