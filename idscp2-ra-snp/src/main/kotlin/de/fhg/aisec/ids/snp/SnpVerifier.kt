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

import com.google.gson.Gson
import com.google.protobuf.ByteString
import de.fhg.aisec.ids.idscp2.idscp_core.drivers.RaVerifierDriver
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.InternalControlMessage
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.fsmListeners.RaVerifierFsmListener
import de.fhg.aisec.ids.snp.SnpAttestdProto.VerifyRequest
import de.fhg.aisec.ids.snp.SnpVerifierProverProto.ProverResponse
import de.fhg.aisec.ids.snp.SnpVerifierProverProto.VerifierChallenge
import de.fhg.aisec.ids.snp.SnpVerifierProverProto.VerifierResult
import org.jose4j.jwt.MalformedClaimException
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.LinkedBlockingQueue

/**
 * An idscp2 ra verifier implementation using SEV-SNP attestation.
 * Information about driver development can be found
 * [here](https://github.com/industrial-data-space/idscp2-jvm/wiki/IDSCP2-Driver-Development#custom-ra-driver).
 */
class SnpVerifier(fsmListener: RaVerifierFsmListener) : RaVerifierDriver<SnpVerifierConfig>(fsmListener) {
    private val messages = LinkedBlockingQueue<ByteArray>()
    private lateinit var config: SnpVerifierConfig

    override fun delegate(message: ByteArray) {
        messages.add(message)
    }

    override fun setConfig(config: SnpVerifierConfig) {
        LOG.trace("Got config")
        this.config = config
    }

    private fun waitForMessage(): ByteArray {
        try {
            return messages.take()
        } catch (e: Exception) {
            if (running) {
                fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_FAILED)
            }
            throw SnpException("Failed to obtain a message from the prover.", e)
        }
    }

    private fun extendPoliciesFromDat(referenceValue: ByteArray): String {
        val jwtConsumer = JwtConsumerBuilder()
            .setSkipSignatureVerification()
            .setSkipAllValidators()
            .build()

        val claims = jwtConsumer.processToClaims(String(fsmListener.remotePeerDat, StandardCharsets.UTF_8))

        var snpPolicies: MutableList<Any>? = try {
            @Suppress("UNCHECKED_CAST")
            claims.getClaimValue("snpPolicies", MutableList::class.java) as MutableList<Any>?
        } catch (e: MalformedClaimException) {
            throw SnpException("Could not parse the SNP policies from the DAT", e)
        }

        if (snpPolicies == null) {
            throw SnpException("The DAT does not contain any SEV-SNP policies")
        }

        val extendedReferenceValue = ByteArray(64)
        referenceValue.copyInto(extendedReferenceValue)

        snpPolicies.add(
            mapOf<String, Any>(
                "type" to "equals",
                "id" to "Report Data matches expected value",
                "params" to mapOf<String, Any>(
                    "field" to "REPORT_DATA",
                    "referenceValue" to Base64.getEncoder().encodeToString(extendedReferenceValue)
                )
            )
        )

        return Gson().toJson(snpPolicies)
    }

    override fun run() {
        if (fsmListener.remotePeerCertificate == null) {
            fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_FAILED)
            throw SnpException("SNP Remote attestation requires the peer certificate to be present.")
        }

        LOG.debug("Starting the attestation process")

        // Connect to the SnpAttestd instance
        val snpAttestdInterface = SnpAttestd(config.snpAttestdAddress)
        LOG.trace("Connected to snp-attestd")

        // Create nonce using a secure RNG
        val nonce = SecureRandomInstance.getNonce(32)

        val verifierChallenge = VerifierChallenge.newBuilder()
            .setNonce(ByteString.copyFrom(nonce))
            .build()

        fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_MSG, verifierChallenge.toByteArray())

        val proverResponseBytes = waitForMessage()
        LOG.trace("Got a response message from the prover")

        val proverResponse = try {
            ProverResponse.parseFrom(proverResponseBytes)
        } catch (e: Exception) {
            fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_FAILED)
            throw SnpException("Got an unexpected or invalid message from the prover. Expected a prover challenge response.", e)
        }

        // Calculate hash that should be contained within the attestation report
        val md = MessageDigest.getInstance("SHA3-512")
        md.update(nonce)
        md.update(config.certificate.getEncoded())
        md.update(fsmListener.remotePeerCertificate!!.getEncoded())
        val digest = md.digest()

        val policies = extendPoliciesFromDat(digest)

        val verifyRequest = VerifyRequest.newBuilder()
            .setReport(proverResponse.report)
            .setVcekCert(proverResponse.vcek)
            .setPolicies(policies)
            .build()

        val verifyResponse = try {
            snpAttestdInterface.rpc.verifyReport(verifyRequest)
        } catch (e: Exception) {
            fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_FAILED)
            throw SnpException("Error communicating with snp-attestd", e)
        }
        LOG.trace("Got a verification result from snp-attestd")

        val verifierResult = VerifierResult.newBuilder()
            .setOk(verifyResponse.ok)
            .build()

        fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_MSG, verifierResult.toByteArray())
        if (verifyResponse.ok) {
            LOG.debug("Attestation succeeded")
            fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_OK)
        } else {
            LOG.debug("Attestation failed")
            fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_FAILED)
        }
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(SnpVerifier::class.java)
        const val SNP_RA_VERIFIER_ID = "SEV-SNP"
    }
}
