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
package de.fhg.aisec.ids.cmc

import org.slf4j.LoggerFactory
import java.io.FileInputStream
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.X509Certificate
import java.util.stream.Collectors

object CmcHelper {
    private val sr = SecureRandom()

    /**
     * Generate a crypto-secure random hex String of length numChars
     *
     * @param numBytes Desired String length
     * @return The generated crypto-secure random hex String
     */
    fun generateNonce(numBytes: Int): ByteArray {
        val randBytes = ByteArray(numBytes)
        sr.nextBytes(randBytes)
        return randBytes
    }

}
