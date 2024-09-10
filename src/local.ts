import { AttestationProviderBase } from "./AttestationProviderBase";
import { SafetyNetAttestationBuilder } from "./SafetyNetAttestationBuilder";

/**
 * Extract the SafetyNet attestation from your request.
 * The token is a base64-encoded string that contains information about the device's integrity and security.
 We recommend sending this as an `x-attestation-header`
 **/
const safetynetAttestationToken: string = ``;

/**
 * Obtain the correct public root certificate that can verify the certificate chain in the attestation response.
 * Certificates are available here: https://pki.goog/repository/
 **/
const googlePublicRootCertificate: string = ``;

const expectedPackageName: string = `test.package.com`;

const safetyNetBuilder = new SafetyNetAttestationBuilder();
const safetyNetAttestation: AttestationProviderBase = safetyNetBuilder
  .setAttestationToken(safetynetAttestationToken)
  .setHostVerifier()
  .setCertChainVerifier({ rootCert: googlePublicRootCertificate })
  .setNonceVerifier({
    // Data supplied during creation of nonce.
    // You must have saved it at server, along with secret used.
    originalData: {
      key: "value",
      anotherKey: "value",
      timestamp: "value",
    },
    secret: "secret",
  })
  .setPayloadTimestampVerifier({ diffInMins: 10 })
  .setApkPackageNameVerifier(expectedPackageName)
  .build();

const safetyNetCheckVerdict = safetyNetAttestation.getDeviceIntegrity();
console.log("Safetynet Check Verdict: ", safetyNetCheckVerdict);

// Perform further actions based on the verdict.
if (safetyNetCheckVerdict) {
  // Safetynet check passed.
  // Proceed with further operations.
} else {
  // Handle failure case.
}
