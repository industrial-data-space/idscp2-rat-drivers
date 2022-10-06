/*-
 * ========================LICENSE_START=================================
 * idscp2-ra-cmc
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
package de.fhg.aisec.ids.cmc.verifier

import de.fhg.aisec.ids.cmc.CmcConfig

/**
 * A configuration class for TPM2d RaVerifier Driver
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class CmcVerifierConfig : CmcConfig() {

    @Suppress("unused")
    class Builder {
        private val config = CmcVerifierConfig()

        fun setCmcHost(host: String): Builder {
            config.cmcHost = host
            return this
        }

        fun setCmcPort(port: Int): Builder {
            config.cmcPort = port
            return this
        }

        fun build(): CmcVerifierConfig {
            return config
        }
    }
}
