### Attestation Server

This package consists of server-side changes for the anti-abuse systems such as SafetyNet API (Android) and Device Check (iOS).

### Usage Guide:

#### Step 1: Obtain a nonce.

```
import { Nonce } from "./nonce/Nonce";

/**
* Provide unique request data for generating a one-time nonce.
**/

const data: Record<string, any> = {
    someKey1: "someValue1",
    someKey2: "someValue2",
};

/**
* A secure string sequence that is hard to guess by an attacker.
* This will be used to encrypt the above data and generate Nonce.
**/

const secret = getSecret();

const generateNonce = () => {
    const myNonce = new Nonce(data, secret);
    return myNonce.create();
}

// Send this nonce back to the client.
const generatedNonce = generateNonce();
```

#### Step 2: Request a SafetyNet attestation.

Send the nonce to SafetyNet API which will return an attestation object.

#### Step 3: Transfer the response to your server.

#### Step 4: Verify the integrity of the device.

```
// Import the modules
import { AttestationProviderBase } from "./AttestationProviderBase";
import { SafetyNetAttestationBuilder } from "./SafetyNetAttestationBuilder";

/**
* Extract the SafetyNet attestation from your request.
* We recommend sending this as an `x-attestation-header`
**/

const safetynetAttestationToken: string = ``;


/**
* Obtain the correct public root certificate that can verify the certificate chain in the attestation response.
* Certificates are available here: https://pki.goog/repository/
**/

const googlePublicRootCertificate: string = ``;


const safetyNetBuilder = new SafetyNetAttestationBuilder();
const safetyNetAttestation: = safetyNetBuilder
                                .setAttestationToken(safetynetAttestationToken)
                                .setHostVerifier()
                                .setCertChainVerifier({ rootCert: googlePublicRootCertificate })
                                .setNonceVerifier()
                                .setPayloadTimestampVerifier({ diffInMins: <payload timestamp could be x minutes old> })
                                .setApkPackageNameVerifier(<your package name>)
                                .build();

/**
* Performs the attestation checks as per builder configuration as above.
* returns true if configured checks were successful. Otherwise throws an appropriate exception.
**/

const finalValue = safetyNetAttestation.getDeviceIntegrity();
console.log("Device is genuine: ", finalValue);

```
