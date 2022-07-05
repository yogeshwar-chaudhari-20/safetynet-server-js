import pkg from "node-forge";
const { pki } = pkg;
import JWT from "jsonwebtoken";
import { SNACert, SNACaStore } from "../safetyNetAttestation/sna.types";

export function getCertificateHost(cert: SNACert) {
  return cert.subject.getField("CN").value;
}

export function certificateFromPem(certStr: string): SNACert {
  return pki.certificateFromPem(certStr);
}

export function createCaStore(certs: SNACert[]) {
  return pki.createCaStore(certs);
}

export function verifyCertificateChain(
  caStore: SNACaStore,
  certs: SNACert[],
  options: any
) {
  return pki.verifyCertificateChain(caStore, certs, options);
}

/**
 * Convers the base64 encoded certificate string to a PEM formatted certificate string.
 * @param certString base64 encoded certificate string
 * @returns PEM formatted certificate string.
 */
export function base64toPem(certString: string) {
  let pemCert = "";

  for (let i = 0; i < certString.length; i += 64) {
    pemCert += certString.slice(i, i + 64) + "\n";
  }

  return (
    "-----BEGIN CERTIFICATE-----\n" + pemCert + "-----END CERTIFICATE-----"
  );
}

/**
 * Extracts the certificate chain from the attestation token header and converts into usable SNACert certificate objects.
 * @param header decoded header string from the attestation token
 * @returns list of SNACert objects
 */

// TODO: Replace the type with SNATokenComponents.header
export const extractCertChain = (header: JWT.JwtHeader) => {
  const sslCertChain: SNACert[] = [];

  if (!header) {
    throw new Error(
      "Missing Header. It is possible that supplied JWT is incorrect. Hence this is empty."
    );
  }

  const numCerts = header.x5c!.length;

  for (let i = 0; i < numCerts; i++) {
    const formattedCert = base64toPem(header.x5c![i]);
    const certificate = pki.certificateFromPem(formattedCert);
    sslCertChain.push(certificate);
  }

  return sslCertChain;
};
