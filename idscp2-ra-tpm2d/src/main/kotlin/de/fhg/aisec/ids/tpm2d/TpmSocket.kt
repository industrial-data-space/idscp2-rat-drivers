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
package de.fhg.aisec.ids.tpm2d

import de.fhg.aisec.ids.tpm2d.messages.TpmAttestation.RemoteToTpm
import de.fhg.aisec.ids.tpm2d.messages.TpmAttestation.TpmToRemote
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.Socket

/**
 * A TPM2d Socket for communication with the Trusted Platform Module
 */
class TpmSocket(host: String, port: Int) : Socket(host, port) {
    private val ins: DataInputStream = DataInputStream(this.inputStream)
    private val outs: DataOutputStream = DataOutputStream(this.outputStream)

    @Throws(IOException::class)
    fun requestAttestation(request: RemoteToTpm): TpmToRemote {
        // Write attestation request message
        val requestBytes = request.toByteArray()
        outs.writeInt(requestBytes.size)
        outs.write(requestBytes)
        // Read attestation result message
        val resultBytes = ByteArray(ins.readInt())
        ins.readFully(resultBytes)
        return TpmToRemote.parseFrom(resultBytes)
    }
}
