import { AttestationProviderBase } from "../AttestationProviderBase";
import { Logger } from "sitka";

const logger: Logger = Logger.getLogger({ name: "SafetyNetAttestation" });

export class SafetyNetAttestation extends AttestationProviderBase {
  constructor() {
    super();
    logger.info("SafetyNetAttestation Created");
  }

  getDeviceIntegrity(): boolean {
    throw new Error("Method not implemented.");
  }
}
