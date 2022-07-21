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
import de.fhg.aisec.ids.idscp2.idscp_core.drivers.RaProverDriver
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.InternalControlMessage
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.fsmListeners.RaProverFsmListener
import de.fhg.aisec.ids.snp.SnpAttestdProto.ReportRequest
import de.fhg.aisec.ids.snp.SnpVerifierProverProto.ProverResponse
import de.fhg.aisec.ids.snp.SnpVerifierProverProto.VerifierChallenge
import de.fhg.aisec.ids.snp.SnpVerifierProverProto.VerifierResult
import org.slf4j.LoggerFactory
import java.security.MessageDigest
import java.util.concurrent.LinkedBlockingQueue

/**
 * An idscp2 ra prover implementation using SEV-SNP attestation.
 * Information about driver development can be found
 * [here](https://github.com/industrial-data-space/idscp2-jvm/wiki/IDSCP2-Driver-Development#custom-ra-driver).
 */
class SnpProver(fsmListener: RaProverFsmListener) : RaProverDriver<SnpProverConfig>(fsmListener) {
    private val messages = LinkedBlockingQueue<ByteArray>()
    private lateinit var config: SnpProverConfig

    override fun delegate(message: ByteArray) {
        messages.add(message)
    }

    override fun setConfig(config: SnpProverConfig) {
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

        // Connect to the SnpAttestd instance
        val snpAttestdInterface = SnpAttestd(config.snpAttestdAddress)

        LOG.trace("Connected to snp-attestd")

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
        md.update(fsmListener.remotePeerCertificate!!.getEncoded())
        md.update(config.certificate.getEncoded())
        val digest = md.digest()

        val reportRequest = ReportRequest.newBuilder()
            .setReportData(ByteString.copyFrom(digest))
            .setIncludeVcekCert(true)
            .build()

        val reportResponse = try {
            snpAttestdInterface.rpc.getReport(reportRequest)
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

        val VerifierResult = try {
            VerifierResult.parseFrom(verifierResultBytes)
        } catch (e: Exception) {
            fsmListener.onRaProverMessage(InternalControlMessage.RA_PROVER_FAILED)
            throw SnpException("Got an unexpected or invalid message from the verifier. Expected a verifier result message.", e)
        }

        if (VerifierResult.ok) {
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
