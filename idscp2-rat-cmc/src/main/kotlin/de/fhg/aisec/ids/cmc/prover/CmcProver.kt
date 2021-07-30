/*-
 * ========================LICENSE_START=================================
 * idscp2-rat-tpm2d
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
package de.fhg.aisec.ids.cmc.prover

import com.google.gson.Gson
import de.fhg.aisec.ids.idscp2.idscp_core.drivers.RatProverDriver
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.InternalControlMessage
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.fsmListeners.RatProverFsmListener
import de.fhg.aisec.ids.cmc.CmcException
import de.fhg.aisec.ids.cmc.CmcSocket
import de.fhg.aisec.ids.cmc.messages.AttestationResult
import org.slf4j.LoggerFactory
import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedBlockingQueue

/**
 * A CMC RatProver Driver implementation that proves its identity to a remote peer using CMC
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class CmcProver(fsmListener: RatProverFsmListener) : RatProverDriver<CmcProverConfig>(fsmListener) {
    private val queue: BlockingQueue<ByteArray> = LinkedBlockingQueue()
    private lateinit var config: CmcProverConfig
    private val gson = Gson()

    override fun setConfig(config: CmcProverConfig) {
        this.config = config
        if (LOG.isDebugEnabled) {
            LOG.debug("CMC expected at " + config.cmcHost + ":" + config.cmcPort)
        }
    }

    override fun delegate(message: ByteArray) {
        if (LOG.isTraceEnabled) {
            LOG.trace("Delegated CMC verifier message to CMC prover")
        }
        queue.add(message)
    }

    private fun waitForVerifierMsg(): ByteArray {
        try {
            return queue.take()
        } catch (e: Exception) {
            if (running) {
                fsmListener.onRatProverMessage(InternalControlMessage.RAT_PROVER_FAILED)
            }
            throw CmcException("Interrupted or invalid message", e)
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
        // CMC Challenge-Response Protocol
        try {
            if (LOG.isDebugEnabled) {
                LOG.debug("Wait for challenge from verifier")
            }
            val ratVerifierMsg = waitForVerifierMsg()

            if (LOG.isDebugEnabled) {
                LOG.debug("Got rat challenge from rat verifier. Starting communication...")
            }

            CmcSocket(config.cmcHost, config.cmcPort).use { cmcSocket ->
                val resultBytes = cmcSocket.request(ratVerifierMsg)
                if (LOG.isDebugEnabled) {
                    LOG.debug("Got CMC response, send response to verifier")
                }
                fsmListener.onRatProverMessage(InternalControlMessage.RAT_PROVER_MSG, resultBytes)
            }

            // wait for result
            if (LOG.isDebugEnabled) {
                LOG.debug("Wait for RAT result from RAT verifier")
            }
            val ratResultJson = String(waitForVerifierMsg())
            if (LOG.isTraceEnabled) {
                LOG.trace(ratResultJson)
            }
            val ratResult = gson.fromJson(ratResultJson, AttestationResult::class.java)

            // notify fsm
            if (ratResult.result) {
                if (LOG.isDebugEnabled) {
                    LOG.debug("CMC attestation succeed")
                }
                fsmListener.onRatProverMessage(InternalControlMessage.RAT_PROVER_OK)
            } else {
                if (LOG.isWarnEnabled) {
                    LOG.warn("CMC attestation failed")
                }
                fsmListener.onRatProverMessage(InternalControlMessage.RAT_PROVER_FAILED)
            }
        } catch (t: Throwable) {
            LOG.error("Error in CMC prover", t)
            throw t
        }
    }

    companion object {
        const val ID = "CMC"
        private val LOG = LoggerFactory.getLogger(CmcProver::class.java)
    }
}
