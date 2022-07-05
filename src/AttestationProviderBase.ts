export abstract class AttestationProviderBase {
  protected _attestationToken!: string;
  protected _rootCert!: string;

  abstract getDeviceIntegrity(): boolean;

  get attestationToken() {
    return this._attestationToken;
  }

  set attestationToken(token: string) {
    this._attestationToken = token;
  }

  get rootCert() {
    return this._rootCert;
  }

  set rootCert(cert: string) {
    this._rootCert = cert;
  }
}
