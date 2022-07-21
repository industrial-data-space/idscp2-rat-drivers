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

import java.security.SecureRandom

/**
 * Provide a global instance of a RNG mainly to fetch nonces
 */
internal object SecureRandomInstance {
    val instance = SecureRandom()

    fun getNonce(len: Int): ByteArray {
        val bytes = ByteArray(len)
        instance.nextBytes(bytes)
        return bytes
    }
}
