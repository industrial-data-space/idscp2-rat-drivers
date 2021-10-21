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

/**
 * A configuration class for TPM2d RaDriver
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
abstract class CmcConfig protected constructor() {

    var cmcHost: String = "localhost"
        protected set

    var cmcPort: Int = DEFAULT_CMC_PORT
        protected set

    companion object {
        const val DEFAULT_CMC_PORT: Int = 9955
    }
}
