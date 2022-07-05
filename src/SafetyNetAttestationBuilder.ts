import { AttestationProviderBase } from "./AttestationProviderBase";
import { SafetyNetAttestation } from "./safetyNetAttestation/SafetyNetAttestation";
import JWT from "jsonwebtoken";
import pkg from "node-forge";

import { Logger } from "sitka";
import jwtWrapper from "./wrappers/jwt.wrapper";
import { extractCertChain } from "./wrappers/cert.lib.wrapper";

const logger: Logger = Logger.getLogger({
  name: "SafetyNetAttestationBuilder",
});

export type SNATokenComponents = JWT.Jwt | null;
export type SNACert = pkg.pki.Certificate;

export interface FeatureFlags {
  verifyHostName: boolean | true;
}

export type AttestOptions = {
  attestationToken: string;
  certChain: SNACert[];
  featureFlags: FeatureFlags;
};

export class SafetyNetAttestationBuilder {
  private _safetyNetAttestation!: SafetyNetAttestation | undefined;
  private _attestationToken!: string;
  private _tokenComponents!: SNATokenComponents;
  private _certChain: SNACert[] = [];
  private _featureFlags!: FeatureFlags;

  constructor() {
    this.reset();
  }

  public reset() {
    logger.info("Builder is reset");
    this._featureFlags = { verifyHostName: false };
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

  public build(): AttestationProviderBase {
    const options: AttestOptions = {
      featureFlags: this._featureFlags,
      certChain: this._certChain,
      attestationToken: this._attestationToken,
    };

    this._safetyNetAttestation = new SafetyNetAttestation(options);
    return this._safetyNetAttestation;
  }
}
