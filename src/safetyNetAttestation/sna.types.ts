import pkg from "node-forge";
import JWT from "jsonwebtoken";

export interface SNAFeatureFlags {
  verifyHostName: boolean | true;
  verifyCertChain: boolean | true;
  verifyPayloadTimestamp: boolean | true;
  verifyApkPackageName: boolean | true;
}

export type SNATokenComponents = {
  header: JWT.JwtHeader;
  payload: JWT.JwtPayload;
  signature: string;
};

export type SNACert = pkg.pki.Certificate;
export type SNACaStore = pkg.pki.CAStore;

export type SNACertChainVerifierOptions = {
  rootCert: string;
};

export type SNATimestampVerifierOptions = {
  diffInMins: number;
};

export type SNAAttestOptions = {
  attestationToken: string;
  tokenComponents: SNATokenComponents;
  certChain: SNACert[];
  rootCert: string;
  timestampVerifierOptions: SNATimestampVerifierOptions | undefined;
  apkPackageName: string;
  featureFlags: SNAFeatureFlags;
};
