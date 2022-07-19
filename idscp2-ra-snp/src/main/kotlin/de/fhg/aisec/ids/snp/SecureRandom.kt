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
