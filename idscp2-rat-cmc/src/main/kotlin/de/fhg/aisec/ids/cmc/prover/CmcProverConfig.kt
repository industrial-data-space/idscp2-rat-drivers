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
package de.fhg.aisec.ids.cmc.prover

import de.fhg.aisec.ids.cmc.CmcConfig
import de.fhg.aisec.ids.cmc.verifier.CmcVerifierConfig

/**
 * A configuration class for TPM2d RatDriver
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class CmcProverConfig : CmcConfig() {

    class Builder {
        private val config = CmcProverConfig()

        fun setCmcHost(host: String): Builder {
            config.cmcHost = host
            return this
        }

        fun setCmcPort(port: Int): Builder {
            config.cmcPort = port
            return this
        }

        fun build(): CmcProverConfig {
            return config
        }
    }
}
