import JWT from "jsonwebtoken";
import { SNATokenComponents } from "../safetyNetAttestation/sna.types";

const extractJWTComponets = (jwtToken: string) => {
  const decodedJWT = JWT.decode(jwtToken, {
    complete: true,
  });

  if (!decodedJWT) {
    throw new Error("Invalid JWT token. Please verify using `https://jwt.io/`");
  }

  return decodedJWT as SNATokenComponents;
};

// TODO: Replace this with getPayloadFieldValue(jwtToken: SNATokenComponents, fieldName: string)
export const getPayloadTimestamp = (jwtToken: SNATokenComponents): string => {
  return jwtToken.payload.timestampMs;
};

// TODO: Replace this with getPayloadFieldValue(jwtToken: SNATokenComponents, fieldName: string)
export const getPackageName = (jwtToken: SNATokenComponents): string => {
  return jwtToken.payload.apkPackageName;
};

// TODO: Replace this with getPayloadFieldValue(jwtToken: SNATokenComponents, fieldName: string)
export const getNonce = (jwtToken: SNATokenComponents): string => {
  return jwtToken.payload.nonce;
};

export default { extractJWTComponets };
