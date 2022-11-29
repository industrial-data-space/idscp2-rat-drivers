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
package de.fhg.aisec.ids.tpm2d.tests

import de.fhg.aisec.ids.idscp2.api.Idscp2EndpointListener
import de.fhg.aisec.ids.idscp2.api.configuration.AttestationConfig
import de.fhg.aisec.ids.idscp2.api.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.api.connection.Idscp2Connection
import de.fhg.aisec.ids.idscp2.api.raregistry.RaProverDriverRegistry
import de.fhg.aisec.ids.idscp2.api.raregistry.RaVerifierDriverRegistry
import de.fhg.aisec.ids.idscp2.api.server.Idscp2Server
import de.fhg.aisec.ids.idscp2.api.server.Idscp2ServerFactory
import de.fhg.aisec.ids.idscp2.core.connection.Idscp2ConnectionImpl
import de.fhg.aisec.ids.idscp2.defaultdrivers.daps.nulldaps.NullDaps
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.NativeTLSDriver
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.NativeTlsConfiguration
import de.fhg.aisec.ids.tpm2d.messages.TpmAttestation
import de.fhg.aisec.ids.tpm2d.prover.TpmProver
import de.fhg.aisec.ids.tpm2d.prover.TpmProverConfig
import de.fhg.aisec.ids.tpm2d.verifier.TpmVerifier
import de.fhg.aisec.ids.tpm2d.verifier.TpmVerifierConfig
import org.awaitility.Awaitility.await
import org.junit.After
import org.junit.Ignore
import org.junit.Test
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.ServerSocket
import java.nio.file.Paths
import java.util.Objects
import java.util.concurrent.CountDownLatch
import kotlin.concurrent.thread

class IntegrationTest {

    private var idscp2Server: Idscp2Server<Idscp2Connection>? = null
    private lateinit var tpmSocket: ServerSocket

    @After
    fun cleanup() {
        tpmSocket.close()
        idscp2Server?.terminate()
        RaProverDriverRegistry.unregisterDriver(TpmProver.ID)
        RaVerifierDriverRegistry.unregisterDriver(TpmVerifier.ID)
    }

    private fun runTpmSimulator(port: Int) {
        this.tpmSocket = ServerSocket(port)
        thread {
            try {
                while (true) {
                    val client = tpmSocket.accept()
                    val ins = DataInputStream(client.inputStream)
                    val outs = DataOutputStream(client.outputStream)

                    val requestBytes = ByteArray(ins.readInt())
                    ins.readFully(requestBytes)
                    val request = TpmAttestation.RemoteToTpm.parseFrom(requestBytes)

                    // TODO
                    val response = TpmAttestation.TpmToRemote.newBuilder()
                        .build()

                    val responseBytes = request.toByteArray()
                    outs.writeInt(requestBytes.size)
                    outs.write(requestBytes)
                    client.close()
                }
            } catch (e: Exception) {
                return@thread
            }
        }
    }

    @Test(timeout = 30000)
    @Ignore
    fun testIdscp2WithTpm() {
        // get keystore paths
        val consumerKeyStorePath = Paths.get(
            Objects.requireNonNull(
                IntegrationTest::class.java.classLoader
                    .getResource("ssl/consumer-keystore.p12")
            ).path
        )
        val providerKeyStorePath = Paths.get(
            Objects.requireNonNull(
                IntegrationTest::class.java.classLoader
                    .getResource("ssl/provider-keystore.p12")
            ).path
        )
        val trustStorePath = Paths.get(
            Objects.requireNonNull(
                IntegrationTest::class.java.classLoader
                    .getResource("ssl/truststore.p12")
            ).path
        )

        val attestationConfig = AttestationConfig.Builder()
            .setSupportedRaSuite(arrayOf(TpmProver.ID))
            .setExpectedRaSuite(arrayOf(TpmVerifier.ID))
            .build()

        val defaultPassword = "password".toCharArray()

        // create client config
        val clientIdscp2Config = Idscp2Configuration.Builder()
            .setDapsDriver(NullDaps())
            .setAttestationConfig(attestationConfig)
            .build()

        val clientTlsConfig = NativeTlsConfiguration.Builder()
            .setKeyStorePath(consumerKeyStorePath)
            .setKeyStorePassword(defaultPassword)
            .setKeyPassword(defaultPassword)
            .setTrustStorePath(trustStorePath)
            .setTrustStorePassword(defaultPassword)
            .setCertificateAlias("1.0.1")
            .setHost("provider-core")
            .build()

        // create server config
        val serverIdscp2Config = Idscp2Configuration.Builder()
            .setDapsDriver(NullDaps())
            .setAttestationConfig(attestationConfig)
            .build()

        val serverTlsConfig = NativeTlsConfiguration.Builder()
            .setKeyStorePath(providerKeyStorePath)
            .setKeyStorePassword(defaultPassword)
            .setKeyPassword(defaultPassword)
            .setTrustStorePath(trustStorePath)
            .setTrustStorePassword(defaultPassword)
            .setCertificateAlias("1.0.1")
            .setHost("provider-core")
            .build()

        // register RAT drivers in registry
        val proverConfig = TpmProverConfig.Builder()
            .setTpmHost("localhost")
            .setTpmPort(TpmProverConfig.DEFAULT_TPM_PORT)
            .build()

        // TODO
        val verifierConfig = TpmVerifierConfig.Builder()
            .build()

        RaProverDriverRegistry.registerDriver(TpmProver.ID, ::TpmProver, proverConfig)
        RaVerifierDriverRegistry.registerDriver(TpmVerifier.ID, ::TpmVerifier, verifierConfig)

        runTpmSimulator(TpmProverConfig.DEFAULT_TPM_PORT)

        val connectionLatch = CountDownLatch(2)

        // start idscp server
        val serverFactory = Idscp2ServerFactory(
            ::Idscp2ConnectionImpl,
            object : Idscp2EndpointListener<Idscp2Connection> {
                override fun onConnection(connection: Idscp2Connection) {
                    connectionLatch.countDown()
                }
            },
            serverIdscp2Config,
            NativeTLSDriver(),
            serverTlsConfig
        )
        idscp2Server = serverFactory.listen()
        await().until { idscp2Server?.isRunning }

        val scDriverClient = NativeTLSDriver<Idscp2Connection>()
        val connectionFuture = scDriverClient.connect(::Idscp2ConnectionImpl, clientIdscp2Config, clientTlsConfig)
        connectionFuture.thenAccept { connection: Idscp2Connection ->
            connection.unlockMessaging()
            connectionLatch.countDown()
        }.exceptionally {
            throw it
        }

        // wait for connection
        connectionLatch.await()

        assert(idscp2Server?.allConnections?.size == 1)
        idscp2Server?.allConnections?.first()?.let {
            await().until { it.isConnected && connectionFuture.get().isConnected }
            it.close()
            await().until { it.isClosed && connectionFuture.get().isClosed }
        }
    }
}
