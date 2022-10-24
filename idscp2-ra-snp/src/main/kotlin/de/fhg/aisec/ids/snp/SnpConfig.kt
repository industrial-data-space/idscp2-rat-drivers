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

import java.security.cert.X509Certificate

/**
 * Configuration parameters for the [SnpProver] class.
 * Instances of this class can be created using [SnpConfig.Builder].
 * @constructor Directly creates the config without using the builder.
 * @param certificate The X.509 certificate used to establish the secure channel.
 * @param snpAttestdAddress The socket address of the `snp-attestd` instance to use.
 * Defaults to TCP port 6778 on the local host.
 */
class SnpConfig(
    val certificate: X509Certificate,
    val snpAttestdHost: String = "127.0.0.1",
    val snpAttestdPort: Int = 6778
) {
    /**
     * Builder class for [SnpConfig].
     */
    class Builder {
        private var host = "127.0.0.1"
        private var port = 6778
        private var certificate: X509Certificate? = null

        /**
         * Set the X.509 certificate used during secure channel establishment.
         * This certificate will be used to bind the attestation report to this endpoint.
         */
        fun setCertificate(value: X509Certificate): Builder {
            certificate = value
            return this
        }

        /**
         * Set the hostname used by `snp-attestd`.
         */
        fun setSnpAttestdHost(value: String): Builder {
            host = value
            return this
        }

        /**
         * Set the port used by `snp-attestd`.
         */
        fun setSnpAttestdPort(value: Int): Builder {
            port = value
            return this
        }

        /**
         * Create the config.
         * At least [setCertificate] must be called beforehand.
         */
        fun build(): SnpConfig {
            return SnpConfig(
                certificate ?: throw SnpException("A certificate must be provided"),
                host,
                port
            )
        }
    }
}
