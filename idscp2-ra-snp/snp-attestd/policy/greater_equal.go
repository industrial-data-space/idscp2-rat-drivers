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
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"

	ar "github.com/industrial-data-space/idscp2-rat-drivers/idscp2-ra-snp/snp-attestd/attestation_report"
)

// The GreaterEqual policy ensures, that a field of the attestation report is greater or equal to a
// minimum value.
// The field and minimum value are both interpreted as little-endian encoded byte arrays.
// The values are then converted to big endian and compared lexicographically.
// This way, the order of numeric data is preserved.
// This policy is useful for fields containing versions like the GUEST_SVN field.
// For TCB versions, use the TcbGreaterEqual policy.
type GreaterEqual struct {
	Field        string `json:"field"`
	MinimumValue []byte `json:"minimumValue"`
}

func GreaterEqualFactory(params json.RawMessage) (Policy, error) {
	var greaterEqual GreaterEqual
	err := json.Unmarshal(params, &greaterEqual)
	return &greaterEqual, err
}

func (p *GreaterEqual) CheckReport(ar *ar.AttestationReport) (ok bool, reason string, err error) {
	selector, ok := fieldSelectors[p.Field]
	if !ok {
		reason = fmt.Sprintf("Unknown attestation report field: %s.", p.Field)
		return
	}

	field := selector.Select(ar)
	if len(field) != len(p.MinimumValue) {
		ok = false
		reason = fmt.Sprintf(
			"The reference data for %s has invalid length. Expected: %d, Got: %d.",
			p.Field,
			len(field),
			len(p.MinimumValue),
		)
		return
	}

	var minimumValue []byte
	copy(minimumValue, p.MinimumValue)

	// Reverse the byte order of the field and minimum value
	// Since we already checked that both have the same length, we can use one loop.
	for i := 0; i < len(field)/2; i++ {
		field[i], field[len(field)-i-1] = field[len(field)-i-1], field[i]
		minimumValue[i], minimumValue[len(field)-i-1] = minimumValue[len(field)-i-1], minimumValue[i]
	}

	// If the field value is less than the reference value.
	if bytes.Compare(field, minimumValue) < 0 {
		ok = false
		reason = fmt.Sprintf(
			"The value of %s was less than the minimum acceptable value.",
			p.Field,
		)
		return
	}

	ok = true
	return
}
