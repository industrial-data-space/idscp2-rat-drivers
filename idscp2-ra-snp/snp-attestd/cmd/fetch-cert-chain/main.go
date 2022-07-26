/*-
 * ========================LICENSE_START=================================
 * snp-attestd
 * %%
 * Copyright (C) 2022 Fraunhofer AISEC
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
package main

import (
	"log"
	"os"
	"path"

	lib "github.com/industrial-data-space/idscp2-rat-drivers/idscp2-ra-snp/snp-attestd"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s <targetDir>\n", os.Args[0])
	}

	targetDir := os.Args[1]

	ask, ark, err := lib.FetchVcekCertChain()
	if err != nil {
		log.Fatalf("Error fetching the VCEK certificate chain: %v", err)
	}

	err = os.WriteFile(path.Join(targetDir, "ask.crt"), ask, 0644)
	if err != nil {
		log.Fatalf("Could not write to the ASK's certificate file: %v", err)
	}

	err = os.WriteFile(path.Join(targetDir, "ark.crt"), ark, 0644)
	if err != nil {
		log.Fatalf("Could not write to the ARK's certificate file: %v", err)
	}
}
