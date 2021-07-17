# IDSCP2 RAT Driver - TPM2d

The TPM 2.0 remote attestation driver implementation for the IDSCP2 protocol in Kotlin.

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