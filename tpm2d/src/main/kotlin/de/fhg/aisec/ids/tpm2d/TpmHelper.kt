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
package de.fhg.aisec.ids.tpm2d

import org.slf4j.LoggerFactory
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.PKIXParameters
import java.security.cert.X509Certificate
import java.util.stream.Collectors

object TpmHelper {
    private val LOG = LoggerFactory.getLogger(TpmHelper::class.java)
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

    /**
     * Calculate SHA-1 hash of (nonce|certificate).
     *
     * @param nonce       The plain, initial nonce
     * @param certificate The certificate to hash-combine with the nonce
     * @return The new nonce, updated with the given certificate using SHA-1
     */
    fun calculateHash(nonce: ByteArray, certificate: Certificate): ByteArray {
        return try {
            val digest = MessageDigest.getInstance("SHA-1")
            digest.update(nonce)
            digest.update(certificate.encoded)
            digest.digest()
        } catch (e1: Exception) {
            LOG.error("Could not create hash of own nonce and local certificate", e1)
            nonce
        }
    }

    internal object ByteArrayUtil {
        private val lookup = arrayOfNulls<String>(256)
        fun toPrintableHexString(bytes: ByteArray): String {
            val s = StringBuilder()
            for (i in bytes.indices) {
                if (i > 0 && i % 16 == 0) {
                    s.append('\n')
                } else {
                    s.append(' ')
                }
                s.append(lookup[bytes[i].toInt() and 0xff])
            }
            return s.toString()
        }

        init {
            for (i in lookup.indices) {
                if (i < 16) {
                    lookup[i] = "0" + Integer.toHexString(i)
                } else {
                    lookup[i] = Integer.toHexString(i)
                }
            }
        }
    }

    /**
     * Load all certificates from trust store
     */
    fun loadCertificates(keyStorePath: Path, keyStorePassword: CharArray): List<X509Certificate> {
        val ks: KeyStore = KeyStore.getInstance("PKCS12")
        Files.newInputStream(keyStorePath).use { keyStoreInputStream ->
            ks.load(keyStoreInputStream, keyStorePassword)
        }
        val trustAnchors = PKIXParameters(ks).trustAnchors
        return trustAnchors.stream().map { it.trustedCert }.collect(Collectors.toList())
    }

    /**
     * Load a specific certificate from key store
     */
    fun loadCertificate(keyStorePath: Path, keyStorePassword: CharArray, keyAlias: String): X509Certificate {
        val ks = KeyStore.getInstance("PKCS12")
        Files.newInputStream(keyStorePath).use { keyStoreInputStream ->
            ks.load(keyStoreInputStream, keyStorePassword)
        }
        // get private key
        val cert = ks.getCertificate(keyAlias) as X509Certificate
        // Probe key alias
        ks.getKey(keyAlias, keyStorePassword)
        return cert
    }
}
