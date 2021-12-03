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
package de.fhg.aisec.ids.tpm2d.tpm2d_prover

/**
 * A configuration class for TPM2d RaDriver
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class TpmProverConfig private constructor() {

    var tpmHost: String = "localhost"
        private set

    var tpmPort: Int = DEFAULT_TPM_PORT
        private set

    class Builder {
        private val config = TpmProverConfig()

        fun setTpmHost(host: String): Builder {
            config.tpmHost = host
            return this
        }

        fun setTpmPort(port: Int): Builder {
            config.tpmPort = port
            return this
        }

        fun build(): TpmProverConfig {
            return config
        }
    }

    companion object {
        const val DEFAULT_TPM_PORT: Int = 9505
    }
}
