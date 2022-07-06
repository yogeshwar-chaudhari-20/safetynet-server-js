import { AttestationProviderBase } from "../AttestationProviderBase";
import { Logger } from "sitka";
import {
  SNAAttestOptions,
  SNAFeatureFlags,
  SNACert,
  SNATokenComponents,
  SNATimestampVerifierOptions,
} from "./sna.types";
import {
  certificateFromPem,
  createCaStore,
  getCertificateHost,
  verifyCertificateChain,
} from "../wrappers/cert.lib.wrapper";
import {
  InvalidCertificateChainError,
  InvalidLeafCertHostNameError,
  PackageNameMismatchError,
  PayloadTimeStampOutOfLimitError,
} from "../errors/SNAErrors";
import { getPackageName, getPayloadTimestamp } from "../wrappers/jwt.wrapper";
import {
  convertMsToMinutes,
  getTimestampDiffInMs,
} from "../wrappers/date.wrapper";

const logger: Logger = Logger.getLogger({ name: "SafetyNetAttestation" });

export class SafetyNetAttestation extends AttestationProviderBase {
  private _tokenComponents!: SNATokenComponents;
  private _certChain!: SNACert[];
  private _timestampVerifierOptions!: SNATimestampVerifierOptions | undefined;
  private _apkPackageName!: string;
  private _featureFlags!: SNAFeatureFlags;

  constructor(options: SNAAttestOptions) {
    super();
    this._attestationToken = options.attestationToken;
    this._tokenComponents = options.tokenComponents;
    this._certChain = options.certChain;
    this._rootCert = options.rootCert;
    this._timestampVerifierOptions = options.timestampVerifierOptions;
    this._apkPackageName = options.apkPackageName;
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

  /**
   * Verifies the certificate chain using trusted root certificate obtained from Google Trust Services.
   * @returns returns true certificate chain can be verified.
   * @throws InvalidLeafCertHostNameError
   */

  public verifyCertChain() {
    logger.info("Verifying certificate chain with root certificate");

    const rootCertX509 = certificateFromPem(this._rootCert);
    const caStore = createCaStore([rootCertX509]);

    const isChainValid = verifyCertificateChain(caStore, this._certChain, {
      validityCheckDate: null,
    });

    if (!isChainValid) {
      logger.error("Certificate chain verification failed");
      throw new InvalidCertificateChainError(
        "Certificate chain verification failed"
      );
    }

    return isChainValid;
  }

  /**
   * Verifies if the difference between payload timestamp and current timestamp is <= acceptable diff in minutes.
   * @returns true if diffence is within acceptable range, false otherwise
   * @throws PayloadTimeStampOutOfLimitError
   */

  public verifyPayloadTimeStamp() {
    logger.info("Verifying payoad timestamp");

    const timestampMs = getPayloadTimestamp(this._tokenComponents);
    const actualDiffInMinutes = convertMsToMinutes(
      getTimestampDiffInMs(Number(timestampMs))
    );

    const isDiffInLimit =
      actualDiffInMinutes <= this._timestampVerifierOptions!.diffInMins;

    if (!isDiffInLimit) {
      logger.error("Payload timestamp verification failed");
      throw new PayloadTimeStampOutOfLimitError(
        `Error Occured while verifying the PayloadTimeStamp ${actualDiffInMinutes}`,
        `(Payload timestamp - current timestamp) > diffInMins`,
        `Try using new attestation token or increasing 'diffInMins' option`
      );
    }

    return isDiffInLimit;
  }

  /**
   * Verifies that the package name in the payload matches with the provided package name.
   * @returns true if payload.apkPackageName == packageName, false otherwise
   * @throws PackageNameMismatchError
   */
  public verifyApkPackageName() {
    logger.info("Verifying payload package name");

    const isPkgMatch =
      this._apkPackageName === getPackageName(this._tokenComponents);

    if (!isPkgMatch) {
      logger.error(
        "Package name in payload does not match the expected package name."
      );
      throw new PackageNameMismatchError("Package name does not match");
    }

    return true;
  }

  performAttestation() {
    if (this._featureFlags.verifyHostName) this.verifyHostName();

    if (this._featureFlags.verifyCertChain) this.verifyCertChain();

    if (this._featureFlags.verifyPayloadTimestamp)
      this.verifyPayloadTimeStamp();

    if (this._featureFlags.verifyApkPackageName) this.verifyApkPackageName();
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

  setFeatureFlags(flags: SNAFeatureFlags) {
    this._featureFlags = flags;
  }
}
