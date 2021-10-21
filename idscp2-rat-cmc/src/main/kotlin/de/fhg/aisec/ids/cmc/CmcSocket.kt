/*-
 * ========================LICENSE_START=================================
 * idscp2-rat-cmc
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

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.Socket

/**
 * Socket for communication with the CMC
 */
class CmcSocket(host: String, port: Int) : Socket(host, port) {
    private val ins: DataInputStream = DataInputStream(this.inputStream)
    private val outs: DataOutputStream = DataOutputStream(this.outputStream)

    @Throws(IOException::class)
    fun request(request: ByteArray): ByteArray {
        // Write attestation request message
        outs.writeInt(request.size)
        outs.write(request)
        // Read attestation result message
        val resultBytes = ByteArray(ins.readInt())
        ins.readFully(resultBytes)
        return resultBytes
    }
}
