/*-
 * ========================LICENSE_START=================================
 * idscp2-ra-tpm2d-example
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
package de.fhg.aisec.ids.tpm2d.example

import de.fhg.aisec.ids.idscp2.api.configuration.AttestationConfig
import de.fhg.aisec.ids.idscp2.api.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.api.drivers.DapsDriver
import de.fhg.aisec.ids.idscp2.daps.aisecdaps.AisecDapsDriver
import de.fhg.aisec.ids.idscp2.daps.aisecdaps.AisecDapsDriverConfig
import de.fhg.aisec.ids.idscp2.daps.aisecdaps.SecurityProfile
import de.fhg.aisec.ids.idscp2.daps.aisecdaps.SecurityRequirements
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.NativeTlsConfiguration
import de.fhg.aisec.ids.tpm2d.prover.TpmProver
import de.fhg.aisec.ids.tpm2d.verifier.TpmVerifier
import java.nio.file.Paths
import java.util.Objects

object RunIdscp2Server {
    @JvmStatic
    fun main(argv: Array<String>) {
        val keyStorePath = Paths.get(
            Objects.requireNonNull(
                RunIdscp2Server::class.java.classLoader
                    .getResource("ssl/provider-keystore.p12")
            ).path
        )

        val trustStorePath = Paths.get(
            Objects.requireNonNull(
                RunIdscp2Server::class.java.classLoader
                    .getResource("ssl/truststore.p12")
            ).path
        )

        val localAttestationConfig = AttestationConfig.Builder()
            .setSupportedRaSuite(arrayOf(TpmProver.ID))
            .setExpectedRaSuite(arrayOf(TpmVerifier.ID))
            .setRaTimeoutDelay(300 * 1000L) // 300 seconds
            .build()

        // create daps config
        val securityRequirements = SecurityRequirements.Builder()
            .setRequiredSecurityLevel(SecurityProfile.INVALID)
            .build()

        val defaultPassword = "password".toCharArray()

        val dapsDriver: DapsDriver = AisecDapsDriver(
            AisecDapsDriverConfig.Builder()
                .setKeyStorePath(keyStorePath)
                .setKeyStorePassword(defaultPassword)
                .setKeyPassword(defaultPassword)
                .setKeyAlias("1")
                .setTrustStorePath(trustStorePath)
                .setTrustStorePassword(defaultPassword)
                .setDapsUrl("https://daps-dev.aisec.fraunhofer.de")
                .setSecurityRequirements(securityRequirements)
                .build()
        )

        val settings = Idscp2Configuration.Builder()
            .setAttestationConfig(localAttestationConfig)
            .setDapsDriver(dapsDriver)
            .build()

        val nativeTlsConfiguration = NativeTlsConfiguration.Builder()
            .setKeyStorePath(keyStorePath)
            .setKeyStorePassword(defaultPassword)
            .setKeyPassword(defaultPassword)
            .setTrustStorePath(trustStorePath)
            .setTrustStorePassword(defaultPassword)
            .setCertificateAlias("1.0.1")
            .setHost("provider-core")
            .build()

        val initiator = Idscp2ServerInitiator()
        initiator.init(settings, nativeTlsConfiguration)
    }
}
