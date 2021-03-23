/*-
 * ========================LICENSE_START=================================
 * tpm2d
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

import de.fhg.aisec.ids.idscp2.idscp_core.drivers.RatProverDriver
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.InternalControlMessage
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.fsmListeners.RatProverFsmListener
import de.fhg.aisec.ids.tpm2d.TpmException
import de.fhg.aisec.ids.tpm2d.TpmHelper
import de.fhg.aisec.ids.tpm2d.TpmMessageFactory
import de.fhg.aisec.ids.tpm2d.TpmSocket
import de.fhg.aisec.ids.tpm2d.messages.TpmAttestation.TpmMessage
import de.fhg.aisec.ids.tpm2d.messages.TpmAttestation.TpmToRemote
import org.slf4j.LoggerFactory
import java.io.IOException
import java.security.cert.X509Certificate
import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedBlockingQueue

/**
 * A TPM2d RatProver Driver implementation that proves its identity to a remote peer using TPM2d
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class TpmProver(fsmListener: RatProverFsmListener) : RatProverDriver<TpmProverConfig>(fsmListener) {
    private val queue: BlockingQueue<ByteArray> = LinkedBlockingQueue()
    private lateinit var config: TpmProverConfig

    override fun setConfig(config: TpmProverConfig) {
        this.config = config
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
                fsmListener.onRatProverMessage(InternalControlMessage.RAT_PROVER_FAILED)
            }
            throw TpmException("Cannot parse TPM message", e)
        }
    }

    /*
     * ******************* Protocol *******************
     *
     * Verifier:
     * -------------------------
     * Generate NonceV
     * create RatChallenge (NonceV, aType, pcr_mask)
     * -------------------------
     *
     * Prover:
     * -------------------------
     * get RatChallenge (NonceV, aType, pcr_mask)
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
     * create RatResult
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

        // wait for RatChallenge from Verifier
        var ratVerifierMsg = waitForVerifierMsg()

        // check if wrapper contains expected rat challenge
        if (!ratVerifierMsg.hasRatChallenge()) {
            // unexpected message
            fsmListener.onRatProverMessage(InternalControlMessage.RAT_PROVER_FAILED)
            throw TpmException("Missing TPM challenge")
        } else if (LOG.isTraceEnabled) {
            LOG.trace("Got rat challenge from rat verifier. Start TPM communication")
        }

        val ratChallenge = ratVerifierMsg.ratChallenge

        // generate hash
        val remoteTransportCert: X509Certificate = fsmListener.remotePeerCertificate
            ?: throw TpmException("Peer transport certificate not available")
        val hash = TpmHelper.calculateHash(ratChallenge.nonce.toByteArray(), remoteTransportCert)
        // generate RemoteToTPM2dRequest
        val tpmRequest = TpmMessageFactory.getRemoteToTPM2dMessage(
            ratChallenge.atype,
            hash,
            if (ratChallenge.hasPcrIndices()) ratChallenge.pcrIndices else 0
        )

        // get TPM response
        val tpmResponse: TpmToRemote = try {
            val tpmSocket = TpmSocket(config.tpmHost, config.tpmPort)
            tpmSocket.requestAttestation(tpmRequest)
        } catch (e: IOException) {
            fsmListener.onRatProverMessage(InternalControlMessage.RAT_PROVER_FAILED)
            throw TpmException("Cannot request attestation from TPM", e)
        }

        // create TpmResponse
        if (LOG.isTraceEnabled) {
            LOG.trace("Send rat response to verifier")
        }
        val response = TpmMessageFactory.getAttestationResponseMessage(tpmResponse).toByteArray()
        fsmListener.onRatProverMessage(InternalControlMessage.RAT_PROVER_MSG, response)

        // wait for result
        ratVerifierMsg = waitForVerifierMsg()

        // check if wrapper contains expected rat result
        if (!ratVerifierMsg.hasRatResult()) {
            fsmListener.onRatProverMessage(InternalControlMessage.RAT_PROVER_FAILED)
            throw TpmException("Missing TPM result")
        } else if (LOG.isTraceEnabled) {
            LOG.trace("Got TPM result from TPM verifier")
        }

        // notify fsm
        if (ratVerifierMsg.ratResult.result) {
            if (LOG.isTraceEnabled) {
                LOG.trace("TPM attestation succeed")
            }
            fsmListener.onRatProverMessage(InternalControlMessage.RAT_PROVER_OK)
        } else {
            if (LOG.isWarnEnabled) {
                LOG.warn("TPM attestation failed")
            }
            fsmListener.onRatProverMessage(InternalControlMessage.RAT_PROVER_FAILED)
        }
    }

    companion object {
        const val ID = "TPM2D"
        private val LOG = LoggerFactory.getLogger(TpmProver::class.java)
    }
}
