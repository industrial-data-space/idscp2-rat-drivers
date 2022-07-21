package policy

import (
	"bytes"
	"encoding/json"
	"fmt"

	ar "github.com/industrial-data-space/idscp2-rat-drivers/idscp2-ra-snp/snp-attestd/attestation_report"
)

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
