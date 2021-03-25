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
package de.fhg.aisec.ids.tpm2d.tpm2d_verifier

import de.fhg.aisec.ids.idscp2.idscp_core.drivers.RatVerifierDriver
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.InternalControlMessage
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.fsmListeners.RatVerifierFsmListener
import de.fhg.aisec.ids.tpm2d.TpmException
import de.fhg.aisec.ids.tpm2d.TpmHelper
import de.fhg.aisec.ids.tpm2d.TpmMessageFactory
import de.fhg.aisec.ids.tpm2d.messages.TpmAttestation.TpmMessage
import de.fhg.aisec.ids.tpm2d.messages.TpmAttestation.TpmResponse
import org.slf4j.LoggerFactory
import tss.tpm.TPMS_ATTEST
import tss.tpm.TPMS_SIGNATURE_RSAPSS
import tss.tpm.TPMS_SIGNATURE_RSASSA
import tss.tpm.TPMT_SIGNATURE
import tss.tpm.TPM_ALG_ID
import java.io.ByteArrayInputStream
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Arrays
import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedBlockingQueue

/**
 * A TPM2d RatVerifier driver that verifies the remote peer's identity using TPM2d
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class TpmVerifier(fsmListener: RatVerifierFsmListener) : RatVerifierDriver<TpmVerifierConfig>(fsmListener) {
    private val queue: BlockingQueue<ByteArray> = LinkedBlockingQueue()
    private lateinit var config: TpmVerifierConfig

    override fun setConfig(config: TpmVerifierConfig) {
        this.config = config
    }

    override fun delegate(message: ByteArray) {
        if (LOG.isTraceEnabled) {
            LOG.trace("Delegated TPM prover message to TPM verifier")
        }
        queue.add(message)
    }

    private fun waitForProverMsg(): TpmMessage {
        try {
            val msg = queue.take()
            return TpmMessage.parseFrom(msg)
        } catch (e: Exception) {
            if (running) {
                fsmListener.onRatVerifierMessage(InternalControlMessage.RAT_VERIFIER_FAILED)
            }
            throw TpmException("Interrupted or invalid message", e)
        }
    }

    private fun sendRatResult(result: Boolean) {
        val ratResult = TpmMessageFactory.getAttestationResultMessage(result).toByteArray()
        fsmListener.onRatVerifierMessage(InternalControlMessage.RAT_VERIFIER_MSG, ratResult)
        if (result) {
            fsmListener.onRatVerifierMessage(InternalControlMessage.RAT_VERIFIER_OK)
        } else {
            fsmListener.onRatVerifierMessage(InternalControlMessage.RAT_VERIFIER_FAILED)
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

        // create rat challenge with fresh nonce
        if (LOG.isTraceEnabled) {
            LOG.trace("Generate and send TPM challenge to remote TPM prover")
        }
        val nonce = TpmHelper.generateNonce(20)

        // send challenge to TPM prover
        val ratChallenge = TpmMessageFactory.getAttestationChallengeMessage(
            nonce, config.expectedAType, config.expectedAttestationMask
        ).toByteArray()
        fsmListener.onRatVerifierMessage(InternalControlMessage.RAT_VERIFIER_MSG, ratChallenge)

        // wait for attestation response
        val ratProverMsg = waitForProverMsg()

        // check if wrapper contains expected rat response
        if (!ratProverMsg.hasRatResponse()) {
            fsmListener.onRatVerifierMessage(InternalControlMessage.RAT_VERIFIER_FAILED)
            throw TpmException("Missing TPM challenge response")
        } else if (LOG.isTraceEnabled) {
            LOG.trace("Got TPM challenge response. Start validation ...")
        }

        val resp = ratProverMsg.ratResponse

        // validate signature
        if (!checkSignature(resp, TpmHelper.calculateHash(nonce, config.localCertificate))) {
            sendRatResult(false)
            throw TpmException("Invalid TPM signature")
        } else if (LOG.isDebugEnabled) {
            LOG.debug("TPM signature valid and certificate trusted")
        }

        // validate pcr values
        if (!checkPcrValues(resp)) {
            sendRatResult(false)
            throw TpmException("Mismatch between pcr values and golden values")
        } else if (LOG.isDebugEnabled) {
            LOG.debug("PCR values trusted")
        }

        // notify fsm about success
        if (LOG.isTraceEnabled) {
            LOG.trace("TPM verification succeed")
        }
        sendRatResult(true)
    }

    private fun checkPcrValues(response: TpmResponse): Boolean {

        try {
            // parse golden values from DAT
            val goldenValues = PcrValues.parse(fsmListener.remotePeerDat)
            if (LOG.isDebugEnabled) {
                LOG.debug("Golden values: $goldenValues")
            }

            // parse pcr from response
            val pcrValues = PcrValues.parse(response.pcrValuesList)
            if (LOG.isDebugEnabled) {
                LOG.debug("Peer PCR values: $pcrValues")
            }

            return pcrValues.isTrusted(goldenValues, config.expectedAType, config.expectedAttestationMask)
        } catch (e: Exception) {
            LOG.error("Cannot check PCR values against golden values", e)
            return false
        }
    }

    private fun checkSignature(response: TpmResponse, hash: ByteArray): Boolean {
        val byteSignature = response.signature.toByteArray()
        val byteCert = response.certificate.toByteArray()
        val byteQuoted = response.quoted.toByteArray()
        if (LOG.isTraceEnabled) {
            LOG.trace("signature: {}", TpmHelper.ByteArrayUtil.toPrintableHexString(byteSignature))
            LOG.trace("cert: {}", TpmHelper.ByteArrayUtil.toPrintableHexString(byteCert))
            LOG.trace("quoted: {}", TpmHelper.ByteArrayUtil.toPrintableHexString(byteQuoted))
        }
        if (byteSignature.isEmpty() || byteCert.isEmpty() || byteQuoted.isEmpty()) {
            LOG.warn("Some required part (signature, cert or quoted) is empty!")
            return false
        }

        return try {
            val certFactory = CertificateFactory.getInstance("X.509")
            val certificate = certFactory.generateCertificate(ByteArrayInputStream(byteCert)) as X509Certificate

            // Load trust anchor certificate
            val rootCertificates = config.caCertificates

            // find the used issuer
            val certificateIssuer = certificate.issuerDN.name

            var trusted = false
            for (caCert in rootCertificates) {
                if (caCert.subjectDN.name == certificateIssuer) {

                    // Verify the TPM certificate
                    try {
                        certificate.verify(caCert.publicKey)
                        trusted = true
                        break
                    } catch (ignore: Exception) {}
                }
            }

            if (!trusted) {
                LOG.warn("TPM Certificate is not trusted")
                return false
            }

            // Construct a new TPMT_SIGNATURE instance from byteSignature bytes
            val tpmtSignature: TPMT_SIGNATURE = try {
                TPMT_SIGNATURE.fromTpm(byteSignature)
            } catch (ex: Exception) {
                LOG.warn(
                    """
                Could not create a TPMT_SIGNATURE from bytes:
                ${TpmHelper.ByteArrayUtil.toPrintableHexString(byteSignature)}
                    """.trimIndent(),
                    ex
                )
                return false
            }

            // Construct a new TPMS_ATTEST instance from byteQuoted bytes
            val tpmsAttest: TPMS_ATTEST = try {
                TPMS_ATTEST.fromTpm(byteQuoted)
            } catch (ex: Exception) {
                LOG.warn(
                    """
                Could not create a TPMS_ATTEST from bytes:
                ${TpmHelper.ByteArrayUtil.toPrintableHexString(byteQuoted)}
                    """.trimIndent(),
                    ex
                )
                return false
            }

            // check hash value (extra data) against expected hash
            val extraBytes = tpmsAttest.extraData
            if (!Arrays.equals(extraBytes, hash)) {
                LOG.warn(
                    """
                The hash (extra data) in TPMS_ATTEST structure is invalid!
                extra data: {}
                hash: {}
                    """.trimIndent(),
                    TpmHelper.ByteArrayUtil.toPrintableHexString(extraBytes),
                    TpmHelper.ByteArrayUtil.toPrintableHexString(hash)
                )

                return false
            }

            // Check signature of attestation
            val tpmSigAlg = tpmtSignature.GetUnionSelector_signature()
            val tpmSigHashAlg: Int
            val tpmSig: ByteArray
            when (tpmSigAlg) {
                TPM_ALG_ID.RSAPSS.toInt() -> {
                    tpmSigHashAlg = (tpmtSignature.signature as TPMS_SIGNATURE_RSAPSS).hash.toInt()
                    tpmSig = (tpmtSignature.signature as TPMS_SIGNATURE_RSAPSS).sig
                }
                TPM_ALG_ID.RSASSA.toInt() -> {
                    tpmSigHashAlg = (tpmtSignature.signature as TPMS_SIGNATURE_RSASSA).hash.toInt()
                    tpmSig = (tpmtSignature.signature as TPMS_SIGNATURE_RSASSA).sig
                }
                else -> {
                    LOG.warn("Unknown or unimplemented signature scheme: " + tpmtSignature.signature.javaClass)
                    return false
                }
            }
            if (tpmSigHashAlg != TPM_ALG_ID.SHA256.toInt()) {
                LOG.warn("Only SHA256withRSA TPM signature hash algorithm is allowed")
                return false
            }
            val sig = Signature.getInstance("SHA256withRSA")
            sig.initVerify(certificate.publicKey)
            sig.update(byteQuoted)
            val result = sig.verify(tpmSig)
            if (!result && LOG.isWarnEnabled) {
                LOG.warn("Attestation signature invalid!")
            }
            result
        } catch (ex: Exception) {
            LOG.warn("Error during attestation validation", ex)
            false
        }
    }

    companion object {
        const val ID = "TPM2D"
        private val LOG = LoggerFactory.getLogger(TpmVerifier::class.java)
    }
}
