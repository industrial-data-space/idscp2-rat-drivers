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
package de.fhg.aisec.ids.tpm2d.example

import de.fhg.aisec.ids.idscp2.default_drivers.secure_channel.tlsv1_3.NativeTLSDriver
import de.fhg.aisec.ids.idscp2.default_drivers.secure_channel.tlsv1_3.NativeTlsConfiguration
import de.fhg.aisec.ids.idscp2.idscp_core.api.Idscp2EndpointListener
import de.fhg.aisec.ids.idscp2.idscp_core.api.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_connection.Idscp2Connection
import de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_connection.Idscp2ConnectionAdapter
import de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_connection.Idscp2ConnectionImpl
import de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_server.Idscp2ServerFactory
import de.fhg.aisec.ids.idscp2.idscp_core.rat_registry.RatProverDriverRegistry
import de.fhg.aisec.ids.idscp2.idscp_core.rat_registry.RatVerifierDriverRegistry
import de.fhg.aisec.ids.tpm2d.TpmHelper
import de.fhg.aisec.ids.tpm2d.messages.TpmAttestation
import de.fhg.aisec.ids.tpm2d.tpm2d_prover.TpmProver
import de.fhg.aisec.ids.tpm2d.tpm2d_prover.TpmProverConfig
import de.fhg.aisec.ids.tpm2d.tpm2d_verifier.TpmVerifier
import de.fhg.aisec.ids.tpm2d.tpm2d_verifier.TpmVerifierConfig
import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets
import java.nio.file.Paths
import java.util.Objects

class Idscp2ServerInitiator : Idscp2EndpointListener<Idscp2Connection> {
    fun init(configuration: Idscp2Configuration, nativeTlsConfiguration: NativeTlsConfiguration) {

        // create secure channel driver
        val secureChannelDriver = NativeTLSDriver<Idscp2Connection>()

        val proverConfig = TpmProverConfig.Builder()
            .setTpmHost("localhost")
            .setTpmPort(TpmProverConfig.DEFAULT_TPM_PORT)
            .build()

        val tpmTrustStore = Paths.get(
            Objects.requireNonNull(
                RunIdscp2Client::class.java.classLoader
                    .getResource("tpm/tpm-truststore.p12")
            ).path
        )

        val verifierConfig = TpmVerifierConfig.Builder()
            .setLocalCertificate(
                TpmHelper.loadCertificate(
                    nativeTlsConfiguration.keyStorePath, nativeTlsConfiguration.keyStorePassword,
                    "1"
                )
            )
            .setExpectedAttestationType(TpmAttestation.IdsAttestationType.BASIC)
            .addRootCaCertificates(tpmTrustStore, "password".toCharArray())
            .build()

        // register rat drivers
        RatProverDriverRegistry.registerDriver(
            TpmProver.ID, ::TpmProver, proverConfig
        )

        RatVerifierDriverRegistry.registerDriver(
            TpmVerifier.ID, ::TpmVerifier, verifierConfig
        )

        // create server config
        val serverConfig = Idscp2ServerFactory(
            ::Idscp2ConnectionImpl,
            this,
            configuration,
            secureChannelDriver,
            nativeTlsConfiguration
        )
        // run idscp2 server
        @Suppress("UNUSED_VARIABLE") val idscp2Server = serverConfig.listen()
    }

    override fun onConnection(connection: Idscp2Connection) {
        LOG.info("Server: New connection with id " + connection.id)
        connection.addConnectionListener(object : Idscp2ConnectionAdapter() {
            override fun onError(t: Throwable) {
                LOG.error("Server connection error occurred", t)
            }

            override fun onClose() {
                LOG.info("Server: Connection with id " + connection.id + " has been closed")
            }
        })
        connection.addMessageListener { c: Idscp2Connection, data: ByteArray ->
            LOG.info("Received ping message: ${String(data, StandardCharsets.UTF_8)}".trimIndent())

            LOG.info("Sending PONG...")
            c.nonBlockingSend("PONG".toByteArray(StandardCharsets.UTF_8))
        }
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(Idscp2ServerInitiator::class.java)
    }

    override fun onError(t: Throwable) {
        // ignore
    }
}
