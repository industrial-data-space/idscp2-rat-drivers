/*-
 * ========================LICENSE_START=================================
 * idscp2-rat-cmc
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
package de.fhg.aisec.ids.cmc.json

data class VerificationResult(
    val type: String,
    val raSuccessful: Boolean,
    val certificationLevel: Int,
    val log: Array<String>
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as VerificationResult

        if (type != other.type) return false
        if (raSuccessful != other.raSuccessful) return false
        if (certificationLevel != other.certificationLevel) return false
        if (!log.contentEquals(other.log)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + raSuccessful.hashCode()
        result = 31 * result + certificationLevel
        result = 31 * result + log.contentHashCode()
        return result
    }
}
