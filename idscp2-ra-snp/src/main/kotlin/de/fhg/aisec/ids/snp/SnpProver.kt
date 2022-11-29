/*-
 * ========================LICENSE_START=================================
 * idscp2-ra-snp
 * %%
 * Copyright (C) 2022 Fraunhofer AISEC
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * =========================LICENSE_END==================================
 */
package de.fhg.aisec.ids.snp

import com.google.protobuf.ByteString
import de.fhg.aisec.ids.idscp2.api.drivers.RaProverDriver
import de.fhg.aisec.ids.idscp2.api.fsm.InternalControlMessage
import de.fhg.aisec.ids.idscp2.api.fsm.RaProverFsmListener
import de.fhg.aisec.ids.snp.SnpAttestdProto.ReportRequest
import de.fhg.aisec.ids.snp.SnpVerifierProverProto.ProverResponse
import de.fhg.aisec.ids.snp.SnpVerifierProverProto.VerifierChallenge
import de.fhg.aisec.ids.snp.SnpVerifierProverProto.VerifierResult
import io.grpc.ManagedChannelBuilder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import java.security.MessageDigest
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * An idscp2 ra prover implementation using SEV-SNP attestation.
 * Information about driver development can be found
 * [here](https://github.com/industrial-data-space/idscp2-jvm/wiki/IDSCP2-Driver-Development#custom-ra-driver).
 */
class SnpProver(fsmListener: RaProverFsmListener) : RaProverDriver<SnpConfig>(fsmListener) {
    private val messages = LinkedBlockingQueue<ByteArray>()
    private lateinit var config: SnpConfig

    override fun delegate(message: ByteArray) {
        messages.add(message)
    }

    override fun setConfig(config: SnpConfig) {
        LOG.trace("Got config")
        this.config = config
    }

    private fun waitForMessage(): ByteArray {
        try {
            return messages.take()
        } catch (e: Exception) {
            if (running) {
                fsmListener.onRaProverMessage(InternalControlMessage.RA_PROVER_FAILED)
            }
            throw SnpException("Failed to obtain a message from the verifier.", e)
        }
    }

    override fun run() {
        if (fsmListener.remotePeerCertificate == null) {
            fsmListener.onRaProverMessage(InternalControlMessage.RA_PROVER_FAILED)
            throw SnpException("SNP Remote attestation requires the peer certificate to be present.")
        }

        LOG.debug("Started the attestation process")

        // Begin by waiting for the verifier's nonce
        val verifierChallengeBytes = waitForMessage()
        LOG.trace("Got a challenge from the verifier")

        val verifierChallenge = try {
            VerifierChallenge.parseFrom(verifierChallengeBytes)
        } catch (e: Exception) {
            fsmListener.onRaProverMessage(InternalControlMessage.RA_PROVER_FAILED)
            throw SnpException("Encountered unexpected or invalid message from verifier. Expected a verifier challenge.", e)
        }

        // Got the nonce from the verifier
        // -> Hash the structure to be embedded into the attestation report
        // Currently, this structure consists of the nonce, the peers TLS certificate and the TLS certificate of this endpoint
        val md = MessageDigest.getInstance("SHA3-512")
        md.update(verifierChallenge.nonce.toByteArray())
        md.update(fsmListener.remotePeerCertificate!!.encoded)
        md.update(config.certificate.encoded)
        val digest = md.digest()

        val reportRequest = ReportRequest.newBuilder()
            .setReportData(ByteString.copyFrom(digest))
            .setIncludeVcekCert(true)
            .build()

        val reportResponse = try {
            runBlocking(Dispatchers.IO) {
                val channel =
                    ManagedChannelBuilder.forAddress(config.snpAttestdHost, config.snpAttestdPort).usePlaintext()
                        .build()
                val attestationResponse =
                    SnpAttestdServiceGrpcKt.SnpAttestdServiceCoroutineStub(channel).getReport(reportRequest)
                channel.shutdown().awaitTermination(5, TimeUnit.SECONDS)
                attestationResponse
            }
        } catch (e: Exception) {
            fsmListener.onRaProverMessage(InternalControlMessage.RA_PROVER_FAILED)
            throw SnpException("Error while communicating with the snp-attestd instance.", e)
        }
        LOG.trace("Got an Attestation Report from snp-attestd")

        val proverResponse = ProverResponse.newBuilder()
            .setReport(reportResponse.report)
            .setVcek(reportResponse.vcekCert)
            .build()

        // Send the response message to the verifier
        fsmListener.onRaProverMessage(InternalControlMessage.RA_PROVER_MSG, proverResponse.toByteArray())

        // Wait for the verifier to return its verdict
        val verifierResultBytes = waitForMessage()
        LOG.trace("Got a response from the verifier")

        val verifierResult = try {
            VerifierResult.parseFrom(verifierResultBytes)
        } catch (e: Exception) {
            fsmListener.onRaProverMessage(InternalControlMessage.RA_PROVER_FAILED)
            throw SnpException("Got an unexpected or invalid message from the verifier. Expected a verifier result message.", e)
        }

        if (verifierResult.ok) {
            LOG.debug("Attestation succeeded")
            fsmListener.onRaProverMessage(InternalControlMessage.RA_PROVER_OK)
        } else {
            LOG.debug("Attestation failed")
            fsmListener.onRaProverMessage(InternalControlMessage.RA_PROVER_FAILED)
        }
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(SnpProver::class.java)
        const val SNP_RA_PROVER_ID = "SEV-SNP"
    }
}
