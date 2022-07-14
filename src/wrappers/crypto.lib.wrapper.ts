import { createHmac } from "crypto";

export function encrypt(data: string, secret: string) {
  return createHmac("sha256", secret).update(data).digest("hex");
}

export function verify(
  encryptedData: string,
  secret: string,
  expectedData: string
) {
  const expectedDigest = createHmac("sha256", secret)
    .update(expectedData)
    .digest("hex");

  return encryptedData === expectedDigest;
}
