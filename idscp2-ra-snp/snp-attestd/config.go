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
package snp_attestd

// The configuration for the snp-attestd service.
type Config struct {
	// Path to the SNP guest device used.
	// The device is usually found at /dev/sev-guest.
	SevDevice string
	// Cache directory to write VCEK certificates to.
	// This directory currently also contains the VCEK certificate chain.
	CacheDir string
	// Only accept verify requests.
	// This is useful when the SNP guest device is not available.
	VerifyOnly bool
}
