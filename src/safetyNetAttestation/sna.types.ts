import pkg from "node-forge";
import JWT from "jsonwebtoken";

export interface SNAFeatureFlags {
  verifyHostName: boolean | true;
}

export type SNATokenComponents = JWT.Jwt | null;
export type SNACert = pkg.pki.Certificate;

export type SNAAttestOptions = {
  attestationToken: string;
  certChain: SNACert[];
  featureFlags: SNAFeatureFlags;
};
