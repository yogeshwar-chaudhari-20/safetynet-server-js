# Attestation Server

## Overview

This package provides server-side functionality for anti-abuse systems, supporting SafetyNet API (Android). It provides cryptographically-signed attestation, confirming various security properties of the device. By implementing SafetyNet checks, you can enhance the security of your app, protect sensitive data, and maintain the integrity of your services.

## Features

- Nonce generation for secure attestation requests
- SafetyNet attestation verification
- Modular and extensible architecture

## Background: Google's SafetyNet API

Google's SafetyNet API is a powerful tool designed to help app developers assess the security and compatibility of the Android environment where their app is running. It's part of Google Play Services and provides a suite of services to protect apps against security threats, including device tampering, bad URLs, potentially harmful apps, and fake users.

Key aspects of SafetyNet API include:

1. **Device Integrity Check**: Verifies if the device is in a known-good state (e.g., not rooted, no custom ROM).

2. **Basic Integrity**: A less stringent check that verifies the device has not been tampered with.

3. **Compatibility Check**: Ensures the device is compatible with your app and Google's services.

4. **Verify Apps**: Checks if the device allows installation of apps from unknown sources.

5. **reCAPTCHA**: Helps protect against automated attacks and bots.

6. **Safe Browsing**: Checks URLs against Google's constantly updated list of unsafe web resources.

Note: While SafetyNet is a robust security measure, it's important to use it as part of a larger security strategy, as no single measure can provide complete protection against all potential threats.

## Usage Guide

### 1. Generate a Nonce

First, create a unique nonce to be used in the attestation process:

```typescript
import { Nonce } from "./nonce/Nonce";

// Provide unique request data for generating a one-time nonce.

const data: Record<string, any> = {
  key: "value",
  anotherKey: "value",
  userSpecificKey: "keeps-nonce-unique",
};

// A secure string sequence that is hard to guess by an attacker.
// This will be used to encrypt the above data and generate Nonce.

const secret = getSecret();

const generateNonce = () => {
  const myNonce = new Nonce(data, secret);
  return myNonce.create();
};

// Send this nonce back to the client.
const generatedNonce = generateNonce();
```

### 2. Request SafetyNet Attestation

Instruct your client application to send the nonce to the SafetyNet API, which will return an attestation object.

### 3. Verify Device Integrity

Once the client sends the attestation response back to your server, verify it as follows:

### 4: Verify the integrity of the device.

```typescript
import { AttestationProviderBase } from "./AttestationProviderBase";
import { SafetyNetAttestationBuilder } from "./SafetyNetAttestationBuilder";

// Attestation token from client (recommended to be sent as 'x-attestation-header')
const safetynetAttestationToken: string = `attestation-token`;

// Google's public root certificate (https://pki.goog/repository/). Use PEM format.
const googlePublicRootCertificate: string = `certerficate.pem`;

const expectedPackageName: string = `your.package.name`;

const safetyNetBuilder = new SafetyNetAttestationBuilder();

const safetyNetAttestation: AttestationProviderBase = safetyNetBuilder
  .setAttestationToken(safetynetAttestationToken)
  .setHostVerifier()
  .setCertChainVerifier({ rootCert: googlePublicRootCertificate })
  .setNonceVerifier({
    originalData: {
      key: "value",
      anotherKey: "value",
      userSpecificKey: "keeps-nonce-unique",
    },
    secret: "secret",
  })
  .setPayloadTimestampVerifier({ diffInMins: 10 })
  .setApkPackageNameVerifier(expectedPackageName)
  .build();

const safetyNetCheckVerdict = safetyNetAttestation.getDeviceIntegrity();
console.log("SafetyNet Check Verdict:", safetyNetCheckVerdict);

// Perform further actions based on the verdict.
if (safetyNetCheckVerdict) {
  // Safetynet check passed.
  // Proceed with further operations.
} else {
  // Handle failure case.
}
```

## API Reference

[Safetynet API](https://www.synopsys.com/blogs/software-security/using-safetynet-api/)
