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

	// If the field value is less than th reference value
	if bytes.Compare(field, p.MinimumValue) < 0 {
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
