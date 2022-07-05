import { AttestationProviderBase } from "./AttestationProviderBase";
import { SafetyNetAttestation } from "./safetyNetAttestation/SafetyNetAttestation";

import { Logger } from "sitka";

const logger: Logger = Logger.getLogger({
  name: "SafetyNetAttestationBuilder",
});

export class SafetyNetAttestationBuilder {
  private _safetyNetAttestation!: SafetyNetAttestation;

  constructor() {
    this.reset();
  }

  public reset() {
    logger.info("Builder is reset");
    this._safetyNetAttestation = new SafetyNetAttestation();
  }

  public build(): AttestationProviderBase {
    this._safetyNetAttestation = new SafetyNetAttestation();
    return this._safetyNetAttestation;
  }
}
