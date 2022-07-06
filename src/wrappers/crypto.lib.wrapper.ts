import { createHmac } from "crypto";

export function encrypt(data: string, secret: string) {
  return createHmac("sha256", secret).update(data).digest("hex");
}
