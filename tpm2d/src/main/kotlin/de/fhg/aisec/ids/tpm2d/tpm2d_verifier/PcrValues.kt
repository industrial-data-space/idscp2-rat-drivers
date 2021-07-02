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

import de.fhg.aisec.ids.tpm2d.messages.TpmAttestation
import de.fhg.aisec.ids.tpm2d.messages.TpmAttestation.IdsAttestationType
import org.jose4j.base64url.Base64
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import java.nio.charset.StandardCharsets
import kotlin.IllegalArgumentException

class PcrValues(private val size: Int) {

    // 24 pcr register
    private val pcrValues = MutableList(size) { PcrEntry() }

    class PcrEntry {

        lateinit var value: ByteArray

        fun isTrusted(other: PcrEntry): Boolean {
            return value.contentEquals(other.value)
        }
    }

    fun isTrusted(goldenValues: PcrValues, aType: IdsAttestationType, mask: Int): Boolean {

        // get the number of pcr registers to be checked
        val count = when (aType) {
            IdsAttestationType.BASIC -> 12
            IdsAttestationType.ALL -> 24
            IdsAttestationType.ADVANCED -> {
                if (mask < 1) {
                    throw IllegalArgumentException("Requested advanced PCR comparison with invalid psr mask")
                }
                mask
            }
        }

        if (size < count) {
            throw IllegalArgumentException("Number of expected PCRs is larger than the number of available PCRs")
        }

        // compare all relevant pcr values
        for (i in 0 until count) {
            if (!pcrValues[i].isTrusted(goldenValues.pcrValues[i])) {
                return false
            }
        }
        return true
    }

    companion object {

        fun parse(pcrValues: List<TpmAttestation.Pcr>): PcrValues {

            if (pcrValues.size > 24) {
                throw IllegalArgumentException("Invalid number of pcr registers in TpmResponse")
            }

            val values = PcrValues(pcrValues.size)
            for (i in pcrValues.indices) {
                values.pcrValues[i].value = pcrValues[i].value.toByteArray()
            }
            return values
        }

        fun parse(dat: ByteArray): PcrValues {

            val jwtConsumer = JwtConsumerBuilder()
                .setSkipSignatureVerification()
                .setSkipAllValidators()
                .build()

            val claims = jwtConsumer.processToClaims(String(dat, StandardCharsets.UTF_8))

            if (!claims.isClaimValueStringList("pcrGoldenValues")) {
                throw IllegalArgumentException("DAT does not contain golden values")
            }

            val goldenValueList = claims.getStringListClaimValue("pcrGoldenValues")

            if (goldenValueList.size != 24) {
                throw IllegalArgumentException("Golden values are not complete")
            }

            val values = PcrValues(24)
            for (i in 0..23) {
                val bytes = Base64.decode(goldenValueList[i])
                values.pcrValues[i].value = bytes
            }

            return values
        }
    }

    private fun ByteArray.toHexString(): String = joinToString(separator = ", ", postfix = "]", prefix = "[") {
            eachByte -> "0x%02x".format(eachByte)
    }

    override fun toString(): String {
        var s = "PCR {\n"
        for (i in 0 until size) {
            val value = this.pcrValues[i].value
            val valueStr = value.toHexString()
            s += "\tpcr_'$i': $valueStr,\n"
        }
        return "$s}\n"
    }
}
