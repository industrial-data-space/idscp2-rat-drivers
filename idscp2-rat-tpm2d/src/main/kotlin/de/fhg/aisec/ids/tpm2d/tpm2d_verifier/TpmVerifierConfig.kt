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
package de.fhg.aisec.ids.tpm2d.tpm2d_verifier

import de.fhg.aisec.ids.tpm2d.TpmHelper
import de.fhg.aisec.ids.tpm2d.messages.TpmAttestation.IdsAttestationType
import java.nio.file.Path
import java.security.cert.X509Certificate
import java.util.Collections

/**
 * A configuration class for TPM2d RaVerifier Driver
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class TpmVerifierConfig private constructor() {
    lateinit var localCertificate: X509Certificate
        private set
    lateinit var caCertificates: List<X509Certificate>
        private set
    var expectedAType = IdsAttestationType.BASIC
        private set
    var expectedAttestationMask = 0
        private set

    class Builder {
        private val config = TpmVerifierConfig()
        private val caCertificates = mutableListOf<X509Certificate>()

        fun setLocalCertificate(localCert: X509Certificate): Builder {
            config.localCertificate = localCert
            return this
        }

        fun addRootCaCertificates(truststore: Path, trustStorePwd: CharArray): Builder {
            caCertificates.addAll(TpmHelper.loadCertificatesFromTruststore(truststore, trustStorePwd))
            return this
        }

        fun addRootCaCertificate(cert: X509Certificate): Builder {
            caCertificates.add(cert)
            return this
        }

        fun addRootCaCertificateFromPem(certPath: Path): Builder {
            caCertificates.add(TpmHelper.loadCertificateFromPem(certPath))
            return this
        }

        fun setExpectedAttestationType(aType: IdsAttestationType): Builder {
            config.expectedAType = aType
            return this
        }

        fun setExpectedAttestationMask(mask: Int): Builder {
            config.expectedAttestationMask = mask
            return this
        }

        fun build(): TpmVerifierConfig {
            config.caCertificates = Collections.unmodifiableList(caCertificates)
            return config
        }
    }
}
