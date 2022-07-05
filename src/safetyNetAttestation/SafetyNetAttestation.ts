import { AttestationProviderBase } from "../AttestationProviderBase";
import { Logger } from "sitka";
import {
  AttestOptions,
  FeatureFlags,
  SNACert,
  SNATokenComponents,
} from "../SafetyNetAttestationBuilder";
import { getCertificateHost } from "../wrappers/cert.lib.wrapper";
import { InvalidLeafCertHostNameError } from "../errors/SNAErrors";

const logger: Logger = Logger.getLogger({ name: "SafetyNetAttestation" });

export class SafetyNetAttestation extends AttestationProviderBase {
  private _tokenComponents!: SNATokenComponents;
  private _certChain!: SNACert[];
  private _featureFlags!: FeatureFlags;

  constructor(options: AttestOptions) {
    super();
    this._attestationToken = options.attestationToken;
    this._certChain = options.certChain;
    this._featureFlags = options.featureFlags;
    logger.info("SafetyNetAttestation Created");
  }

  /**
   * Verifies that hostname of leaf certificate.
   * @returns true if hostname is `attest.android.com`
   * @throws InvalidLeafCertHostNameError
   */
  public verifyHostName() {
    logger.info("Verifying hostname of leaf certificate");

    const hostname = getCertificateHost(this._certChain[0]);
    const isHostValid = hostname === "attest.android.com";

    if (!isHostValid) {
      logger.error("Hostname verification failed");
      throw new InvalidLeafCertHostNameError(
        "verifyLeafCert: Leaf certificate not issued by `attest.android.com`",
        `Extracted CN: ${hostname}`
      );
    }

    return isHostValid;
  }

  performAttestation() {
    if (this._featureFlags.verifyHostName) {
      this.verifyHostName();
    }
  }

  getDeviceIntegrity(): boolean {
    this.performAttestation();
    return true;
  }

  get tokenComponents() {
    return this._tokenComponents;
  }

  set tokenComponents(comps: SNATokenComponents) {
    this._tokenComponents = comps;
  }

  setFeatureFlags(flags: FeatureFlags) {
    this._featureFlags = flags;
  }
}
