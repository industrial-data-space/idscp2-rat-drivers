/*-
 * ========================LICENSE_START=================================
 * idscp2-ra-tpm2d
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
package de.fhg.aisec.ids.tpm2d.tpm2d_prover

import de.fhg.aisec.ids.idscp2.idscp_core.drivers.RaProverDriver
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.InternalControlMessage
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.fsmListeners.RaProverFsmListener
import de.fhg.aisec.ids.tpm2d.TpmException
import de.fhg.aisec.ids.tpm2d.TpmHelper
import de.fhg.aisec.ids.tpm2d.TpmMessageFactory
import de.fhg.aisec.ids.tpm2d.TpmSocket
import de.fhg.aisec.ids.tpm2d.messages.TpmAttestation.TpmMessage
import de.fhg.aisec.ids.tpm2d.messages.TpmAttestation.TpmToRemote
import org.slf4j.LoggerFactory
import java.io.IOException
import java.security.cert.X509Certificate
import java.util.Arrays
import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedBlockingQueue

/**
 * A TPM2d RaProver Driver implementation that proves its identity to a remote peer using TPM2d
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class TpmProver(fsmListener: RaProverFsmListener) : RaProverDriver<TpmProverConfig>(fsmListener) {
    private val queue: BlockingQueue<ByteArray> = LinkedBlockingQueue()
    private lateinit var config: TpmProverConfig

    override fun setConfig(config: TpmProverConfig) {
        this.config = config
        LOG.debug("TPM2d expected at " + config.tpmHost + ":" + config.tpmPort)
    }

    override fun delegate(message: ByteArray) {
        if (LOG.isTraceEnabled) {
            LOG.trace("Delegated TPM verifier message to TPM prover")
        }
        queue.add(message)
    }

    private fun waitForVerifierMsg(): TpmMessage {
        try {
            val msg = queue.take()
            return TpmMessage.parseFrom(msg)
        } catch (e: Exception) {
            if (running) {
                fsmListener.onRaProverMessage(InternalControlMessage.RA_PROVER_FAILED)
            }
            throw TpmException("Interrupted or invalid message", e)
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
        // TPM Challenge-Response Protocol
        try {
            // wait for RaChallenge from Verifier
            LOG.debug("Wait for TPM challenge from RAT verifier")
            var ratVerifierMsg = waitForVerifierMsg()

            // check if wrapper contains expected rat challenge
            if (!ratVerifierMsg.hasRatChallenge()) {
                // unexpected message
                fsmListener.onRaProverMessage(InternalControlMessage.RA_PROVER_FAILED)
                throw TpmException("Missing TPM challenge")
            } else if (LOG.isDebugEnabled) {
                LOG.debug("Got rat challenge from rat verifier. Start TPM communication")
            }

            val ratChallenge = ratVerifierMsg.ratChallenge

            // generate hash
            LOG.debug("Generate hash of peer's transport certificate and nonce from the TPM challenge")
            val remoteTransportCert: X509Certificate = fsmListener.remotePeerCertificate
                ?: throw TpmException("Peer transport certificate not available")
            LOG.debug("Nonce: " + Arrays.toString(ratChallenge.nonce.toByteArray()))
            if (LOG.isTraceEnabled) {
                LOG.trace("Peer's certificate: $remoteTransportCert")
            }
            val hash = TpmHelper.calculateHash(ratChallenge.nonce.toByteArray(), remoteTransportCert)
            // generate RemoteToTPM2dRequest
            val tpmRequest = TpmMessageFactory.getRemoteToTPM2dMessage(
                ratChallenge.atype,
                hash,
                if (ratChallenge.hasPcrIndices()) ratChallenge.pcrIndices else 0
            )

            // get TPM response
            val tpmResponse: TpmToRemote = try {
                LOG.debug("Send TPM request message to TPM2d")
                val tpmSocket = TpmSocket(config.tpmHost, config.tpmPort)
                tpmSocket.requestAttestation(tpmRequest)
            } catch (e: IOException) {
                fsmListener.onRaProverMessage(InternalControlMessage.RA_PROVER_FAILED)
                throw TpmException("Cannot request attestation from TPM", e)
            }

            // create TpmResponse
            if (LOG.isDebugEnabled) {
                LOG.debug("Got TPM response, send TPM response to verifier")
            }
            val response = TpmMessageFactory.getAttestationResponseMessage(tpmResponse).toByteArray()
            fsmListener.onRaProverMessage(InternalControlMessage.RA_PROVER_MSG, response)

            // wait for result
            LOG.debug("Wait for RAT result from RAT verifier")
            ratVerifierMsg = waitForVerifierMsg()

            // check if wrapper contains expected rat result
            if (!ratVerifierMsg.hasRatResult()) {
                fsmListener.onRaProverMessage(InternalControlMessage.RA_PROVER_FAILED)
                throw TpmException("Missing TPM result in RAT verifier message")
            } else if (LOG.isDebugEnabled) {
                LOG.debug("Got TPM result from TPM verifier")
            }

            // notify fsm
            if (ratVerifierMsg.ratResult.result) {
                if (LOG.isDebugEnabled) {
                    LOG.debug("TPM attestation succeed")
                }
                fsmListener.onRaProverMessage(InternalControlMessage.RA_PROVER_OK)
            } else {
                if (LOG.isWarnEnabled) {
                    LOG.warn("TPM attestation failed")
                }
                fsmListener.onRaProverMessage(InternalControlMessage.RA_PROVER_FAILED)
            }
        } catch (t: Throwable) {
            LOG.error("Error in TPM prover", t)
            throw t
        }
    }

    companion object {
        const val ID = "TPM"
        private val LOG = LoggerFactory.getLogger(TpmProver::class.java)
    }
}
