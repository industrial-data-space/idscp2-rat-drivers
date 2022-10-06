/*-
 * ========================LICENSE_START=================================
 * idscp2-ra-cmc
 * %%
 * Copyright (C) 2021 Fraunhofer AISEC
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
package de.fhg.aisec.ids.cmc.verifier

import com.google.protobuf.ByteString
import de.fhg.aisec.ids.cmc.CmcException
import de.fhg.aisec.ids.cmc.CmcHelper
import de.fhg.aisec.ids.cmc.CmcHelper.GSON
import de.fhg.aisec.ids.cmc.json.VerificationResult
import de.fhg.aisec.ids.cmcinterface.AttestationRequest
import de.fhg.aisec.ids.cmcinterface.CMCServiceGrpcKt
import de.fhg.aisec.ids.cmcinterface.Status
import de.fhg.aisec.ids.cmcinterface.VerificationRequest
import de.fhg.aisec.ids.cmcinterface.VerificationResponse
import de.fhg.aisec.ids.idscp2.core.drivers.RaVerifierDriver
import de.fhg.aisec.ids.idscp2.core.fsm.InternalControlMessage
import de.fhg.aisec.ids.idscp2.core.fsm.fsmListeners.RaVerifierFsmListener
import io.grpc.ManagedChannelBuilder
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets
import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * A CMC RaVerifier driver that verifies the remote peer's identity using CMC
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
@Suppress("unused")
class CmcVerifier(fsmListener: RaVerifierFsmListener) : RaVerifierDriver<CmcVerifierConfig>(fsmListener) {
    private val queue: BlockingQueue<ByteArray> = LinkedBlockingQueue()
    private lateinit var config: CmcVerifierConfig

    override fun setConfig(config: CmcVerifierConfig) {
        this.config = config
    }

    override fun delegate(message: ByteArray) {
        if (LOG.isTraceEnabled) {
            LOG.trace("Delegated CMC prover message to CMC verifier")
        }
        queue.add(message)
    }

    private fun waitForAttestationReport(): ByteArray {
        try {
            return queue.take()
        } catch (e: Exception) {
            if (running) {
                fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_FAILED)
            }
            throw CmcException("Interrupted or invalid message", e)
        }
    }

    private fun sendRaResult(verificationResponse: VerificationResponse) {
        fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_MSG, verificationResponse.toByteArray())
        if (verificationResponse.status == Status.OK) {
            val verificationResult = GSON.fromJson(
                verificationResponse.verificationResult.toString(StandardCharsets.UTF_8),
                VerificationResult::class.java
            )
            if (verificationResult.raSuccessful) {
                if (LOG.isDebugEnabled) {
                    LOG.debug("Verifier: CMC verification succeeded, result: {}", verificationResult)
                }
                fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_OK)
            } else {
                if (LOG.isDebugEnabled) {
                    LOG.debug("Verifier: CMC verification failed, result: {}", verificationResult)
                }
                fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_FAILED)
            }
        } else {
            if (LOG.isDebugEnabled) {
                LOG.debug("Verifier: CMC verification request failed")
            }
            fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_FAILED)
        }
    }

    /*
     * ******************* Protocol *******************
     *
     * Verifier:
     * -------------------------
     * Generate NonceV
     * create RaChallenge (NonceV, aType, pcr_mask)
     * -------------------------
     *
     * Prover:
     * -------------------------
     * get RaChallenge (NonceV, aType, pcr_mask)
     * hash = calculateHash(nonceV, certV)
     * req = generate RemoteToTpm (hash, aType, pcr_mask)
     * TpmToRemote = tpmSocket.attestationRequest(req)
     * create TpmResponse from TpmToRemote
     * -------------------------
     *
     * Verifier:
     * -------------------------
     * get TpmResponse
     * hash = calculateHash(nonceV, certV)
     * check signature(response, hash)
     * check golden values from DAT (aType, response)
     * create RaResult
     * -------------------------
     *
     * Prover:
     * -------------------------
     * get TpmResult
     * -------------------------
     *
     */
    override fun run() {
        // CMC Challenge-Response Protocol
        try {
            // create rat challenge with fresh nonce
            if (LOG.isDebugEnabled) {
                LOG.debug("Generate and send challenge to remote prover")
            }
            val nonce = CmcHelper.generateNonce(20)
            if (LOG.isDebugEnabled) {
                LOG.debug("Challenge nonce is: $nonce")
            }

            val raRequest = AttestationRequest.newBuilder()
                .setNonce(ByteString.copyFrom(nonce))
                .build()
            if (LOG.isTraceEnabled) {
                println(raRequest)
            }
            // send request to prover
            fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_MSG, raRequest.toByteArray())

            // wait for attestation response
            if (LOG.isDebugEnabled) {
                LOG.debug("Wait for RAT prover message with attestation response")
            }
            // Receive JWS, packed as JSON, from prover
            val attestationReport = waitForAttestationReport()
            if (LOG.isDebugEnabled) {
                LOG.debug("Got challenge response. Start validation...")
            }

            val verificationRequest = VerificationRequest.newBuilder()
                .setNonce(ByteString.copyFrom(nonce))
                .setAttestationReport(ByteString.copyFrom(attestationReport))
                .build()
            if (LOG.isTraceEnabled) {
                println(verificationRequest)
            }

            val verificationResponse = runBlocking {
                val channel = ManagedChannelBuilder.forAddress(config.cmcHost, config.cmcPort).usePlaintext().build()
                val verificationResponse = CMCServiceGrpcKt.CMCServiceCoroutineStub(channel).verify(verificationRequest)
                channel.shutdown().awaitTermination(5, TimeUnit.SECONDS)
                verificationResponse
            }

            // Send verification response to prover
            sendRaResult(verificationResponse)
        } catch (t: Throwable) {
            LOG.error("Error in CMC Verifier", t)
            throw t
        }
    }

    companion object {
        const val ID = "CMC"
        private val LOG = LoggerFactory.getLogger(CmcVerifier::class.java)
    }
}
