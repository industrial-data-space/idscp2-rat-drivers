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
package attestation_report

import "encoding/binary"

// The non-reserved fields of the TCB version struct defined in
// https://www.amd.com/system/files/TechDocs/56860.pdf, Table 3
type TcbVersion struct {
	BootLoader uint8
	Tee        uint8
	// reserved [4]uint8
	Snp       uint8
	Microcode uint8
}

// Decode a TCB version from the raw value obtained from the attestation report.
func DecodeTcbVersion(raw uint64) TcbVersion {
	var tcb TcbVersion
	bytes := [8]byte{}
	binary.LittleEndian.PutUint64(bytes[:], raw)
	tcb.BootLoader = bytes[0]
	tcb.Tee = bytes[1]
	tcb.Snp = bytes[6]
	tcb.Microcode = bytes[7]
	return tcb
}
