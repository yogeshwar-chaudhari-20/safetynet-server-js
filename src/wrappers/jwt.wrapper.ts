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

export default { extractJWTComponets };
