# IDSCP2 RAT Driver - TPM

The tpm driver implementation for the IDSCP2 protocol in Kotlin.

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

// set the attestation type: BASIC, ADVANCED or ALL
fun setExpectedAttestationType(aType: IdsAttestationType): Builder

fun setExpectedAttestationMask(mask: Int): Builder

fun build(): TpmVerifierConfig
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

## Example Run

To run the examples from *src/main/kotlin/examples* the following steps have to be done:

1. Change your host file (/etc/hosts) and add the following to ensure the transport certificates are working:
```
   127.0.0.1       consumer-core
   127.0.0.1       provider-core
```
2. Start the tpmsim at tpmsim/ via the docker-compose file
3. Install gradle (https://gradle.org/install/)
4. Build project from tpm2d/ directory:
```
gradle build
```   
5. Run the example IDSCP2 server:
```
gradle TpmExampleServer
``` 
6. Run the example IDSCP2 client:
```
gradle TpmExampleClient
``` 