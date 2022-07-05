import { AttestationProviderBase } from "./AttestationProviderBase";
import { SafetyNetAttestation } from "./safetyNetAttestation/SafetyNetAttestation";

import { Logger } from "sitka";
import jwtWrapper from "./wrappers/jwt.wrapper";
import { extractCertChain } from "./wrappers/cert.lib.wrapper";
import {
  SNAAttestOptions,
  SNATokenComponents,
  SNACert,
  SNACertChainVerifierOptions,
  SNAFeatureFlags,
} from "./safetyNetAttestation/sna.types";

const logger: Logger = Logger.getLogger({
  name: "SafetyNetAttestationBuilder",
});
export class SafetyNetAttestationBuilder {
  private _safetyNetAttestation!: SafetyNetAttestation | undefined;
  private _attestationToken!: string;
  private _tokenComponents!: SNATokenComponents;
  private _certChain: SNACert[] = [];
  private _rootCert!: string;
  private _featureFlags!: SNAFeatureFlags;

  constructor() {
    this.reset();
  }

  public reset() {
    logger.info("Builder is reset");
    this._featureFlags = { verifyHostName: false, verifyCertChain: false };
    this._safetyNetAttestation = undefined;
  }

  public setAttestationToken(token: string) {
    this._tokenComponents = jwtWrapper.extractJWTComponets(token);
    this._attestationToken = token;
    return this;
  }

  public setHostVerifier() {
    this._certChain = extractCertChain(this._tokenComponents!.header!);
    this._featureFlags.verifyHostName = true;
    return this;
  }

  public setCertChainVerifier(options: SNACertChainVerifierOptions) {
    this._rootCert = options.rootCert;
    this._featureFlags.verifyCertChain = true;
    return this;
  }

  public build(): AttestationProviderBase {
    const options: SNAAttestOptions = {
      featureFlags: this._featureFlags,
      certChain: this._certChain,
      rootCert: this._rootCert,
      attestationToken: this._attestationToken,
    };

    this._safetyNetAttestation = new SafetyNetAttestation(options);
    return this._safetyNetAttestation;
  }
}
