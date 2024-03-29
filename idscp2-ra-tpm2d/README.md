# IDSCP2 RAT Driver - TPM2d

The TPM 2.0 remote attestation driver implementation for the IDSCP2 protocol in Kotlin.

## Configuring TPM drivers

### TPM Verifier

A builder pattern is provided for configuring the TPM verifier driver:

```kotlin   
// set the local transport certificate used for the hash to avoid reply attacks
fun setLocalCertificate(localCert: X509Certificate): Builder

// add all root ca cert from a given truststore, used for verifying TPM cert
fun addRootCaCertificates(truststore: Path, trustStorePwd: CharArray): Builder

// add a single root ca cert, used for verifying TPM cert
fun addRootCaCertificate(cert: X509Certificate): Builder

// add a single root ca cert from pem file, used for verifying TPM cert
fun addRootCaCertificateFromPem(certPath: Path): Builder

// set the attestation type: BASIC, ADVANCED or ALL
fun setExpectedAttestationType(aType: IdsAttestationType): Builder

fun setExpectedAttestationMask(mask: Int): Builder

fun build(): TpmVerifierConfig
```

The provers TPM certificate has to be sign by a CA certificate. Since the verifier configuration
is per connector, multiple root CA certificate might be available to verify certificates
of multiple other connectors. For this purpose, all the root CA certs can be added to the config individually
using the *addRootCaCertificate* or *addRootCaCertificateFromPem* or all the root CA certs can be collected
into a single pkcs12 truststore. To add a certificate into a truststore, use *keytool*:

```
keytool -importcert -storetype PKCS12 -keystore $TPM-truststore.p12 \
  -storepass $TRUSTSTORE_PASSWORD -alias $CA_ALIAS -file $CA_CERT.pem -noprompt
```

### TPM prover

A builder pattern is provided for configuring the TPM prover driver:

```kotlin   
// set the host where the tpm2d socket is running, e.g. localhost
fun setTpmHost(host: String): Builder

// set the port where the tpm2d socket is running, e.g. 9505
fun setTpmPort(port: Int): Builder

fun build(): TpmProverConfig
```

## Usage

The TPM driver implementation can be integrated into an IDSCP2 peer
as described in the User API / User Documentation at
[IDSCP2 Documentation](https://github.com/industrial-data-space/idscp2-java/wiki):

````kotlin
// create prover config, expecting tpm2d at localhost:9505
val proverConfig = TpmProverConfig.Builder()
    .setTpmHost("localhost")
    .setTpmPort(TpmProverConfig.DEFAULT_TPM_PORT)
    .build()

// create verifier config 
val verifierConfig = TpmVerifierConfig.Builder()
    .setLocalCertificate(cert)
    .setExpectedAttestationType(TpmAttestation.IdsAttestationType.ALL)
    .addRootCaCertificates(tpmTrustStore, "password".toCharArray())
    .build()

// register rat drivers at registries
RatProverDriverRegistry.registerDriver(
    TpmProver.ID, ::TpmProver, proverConfig
)

RatVerifierDriverRegistry.registerDriver(
    TpmVerifier.ID, ::TpmVerifier, verifierConfig
)
````