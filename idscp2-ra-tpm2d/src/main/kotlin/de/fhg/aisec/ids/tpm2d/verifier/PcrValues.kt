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
package de.fhg.aisec.ids.tpm2d.verifier

import de.fhg.aisec.ids.tpm2d.messages.TpmAttestation
import de.fhg.aisec.ids.tpm2d.messages.TpmAttestation.IdsAttestationType
import de.fhg.aisec.ids.tpm2d.toHexString
import org.jose4j.base64url.Base64
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import java.nio.charset.StandardCharsets
import java.util.Collections.unmodifiableList

class PcrValues {

    private val pcrValues: List<PcrEntry>

    data class PcrEntry(val number: Int, val value: ByteArray) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as PcrEntry

            if (number != other.number) return false
            if (!value.contentEquals(other.value)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = number
            result = 31 * result + value.contentHashCode()
            return result
        }
    }

    constructor(pcrValues: List<TpmAttestation.Pcr>) {

        if (pcrValues.size > 24) {
            throw IllegalArgumentException("Invalid number of pcr registers in TpmResponse")
        }

        this.pcrValues = unmodifiableList(
            pcrValues.map { PcrEntry(it.number, it.value.toByteArray()) }.sortedBy { it.number }
        )
    }

    constructor(dat: ByteArray) {

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

        this.pcrValues = unmodifiableList(
            goldenValueList.mapIndexed { n, v ->
                PcrEntry(n, Base64.decode(v))
            }
        )
    }

    fun isTrusted(goldenValues: PcrValues, aType: IdsAttestationType, mask: Int): Boolean {
        // get the number of pcr registers to be checked
        val count = when (aType) {
            IdsAttestationType.BASIC -> 12
            IdsAttestationType.ALL -> 24
            IdsAttestationType.ADVANCED -> {
                if (mask < 1) {
                    throw IllegalArgumentException("Requested advanced PCR comparison with invalid PCR mask")
                }
                mask.countOneBits()
            }
        }

        if (this.pcrValues.size < count) {
            throw IllegalArgumentException(
                "Expected $count PCR values, but only ${this.pcrValues.size} values are available."
            )
        }

        // compare all relevant pcr values
        if (aType == IdsAttestationType.ADVANCED) {
            val biMask = mask.toBigInteger()
            pcrValues.forEach {
                if (biMask.testBit(it.number) && it != goldenValues.pcrValues[it.number]) {
                    return false
                }
            }
        } else {
            for (i in 0 until count) {
                if (pcrValues[i] != goldenValues.pcrValues[i]) {
                    return false
                }
            }
        }
        return true
    }

    override fun toString(): String {
        return "PCR {\n" + pcrValues.joinToString("\n") { "pcr_${it.number}: ${it.value.toHexString()}" } + "\n}"
    }
}
