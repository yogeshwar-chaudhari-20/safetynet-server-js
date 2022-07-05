import pkg from "node-forge";
import JWT from "jsonwebtoken";

export interface SNAFeatureFlags {
  verifyHostName: boolean | true;
  verifyCertChain: boolean | true;
}

export type SNATokenComponents = JWT.Jwt | null;
export type SNACert = pkg.pki.Certificate;
export type SNACaStore = pkg.pki.CAStore;
export type SNACertChainVerifierOptions = {
  rootCert: string;
};

export type SNAAttestOptions = {
  attestationToken: string;
  certChain: SNACert[];
  rootCert: string;
  featureFlags: SNAFeatureFlags;
};
