package de.fhg.aisec.ids.snp

import java.net.InetSocketAddress
import java.net.SocketAddress
import java.security.cert.X509Certificate

/**
 * Configuration parameters for the [SnpVerifier] class.
 * Instances of this class can be created using [SnpVerifierConfig.Builder].
 * @constructor Directly creates the config witout using the builder.
 * @param certificate The X.509 certificate used to establish the secure channel.
 * @param snpAttestdAddress The socket address of the `snp-attestd` instance to use.
 * Defaults to TCP port 6778 on the local host.
 */
class SnpVerifierConfig(
    val certificate: X509Certificate,
    val snpAttestdAddress: SocketAddress = InetSocketAddress("127.0.0.1", 6778),
) {
    /**
     * Builder class for [SnpVerifierConfig].
     */
    class Builder {
        private var certificate: X509Certificate? = null
        private var address: SocketAddress? = null
        private var host = "127.0.0.1"
        private var port = 6778

        /**
         * Set the X.509 certificate used during secure channel establishment.
         * This certificate will be used to bind the attestation report to this endpoint.
         */
        fun setCertificate(value: X509Certificate): Builder {
            certificate = value
            return this
        }

        /**
         * Set the address used by `snp-attestd`.
         * This option overrides [setSnpAttestdHost] and [setSnpAttestdPort].
         */
        fun setSnpAttestdAddress(value: SocketAddress): Builder {
            address = value
            return this
        }

        /**
         * Set the hostname used by `snp-attestd`.
         * This option overrides [setSnpAttestdAddress].
         */
        fun setSnpAttestdHost(value: String): Builder {
            host = value
            return this
        }

        /**
         * Set the port used by `snp-attestd`.
         * This option overrides [setSnpAttestdAddress].
         */
        fun setSnpAttestdPort(value: Int): Builder {
            port = value
            return this
        }

        /**
         * Create the config.
         * At least [setCertificate] must be called beforehand.
         */
        fun build(): SnpVerifierConfig {
            return SnpVerifierConfig(
                certificate ?: throw SnpException("A certificate must be provided."),
                address ?: InetSocketAddress(host, port),
            )
        }
    }
}
