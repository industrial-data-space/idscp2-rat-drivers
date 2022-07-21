package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	ar "github.com/industrial-data-space/idscp2-rat-drivers/idscp2-ra-snp/snp-attestd/attestation_report"
)

// The Equals policy ensures, that a field of the attestation report contains a reference value.
// The field is compared as a little-endian encoded byte array.
// This policy is usefull for static fields like the launch measurement or report data.
type Equals struct {
	Field          string `json:"field"`
	ReferenceValue []byte `json:"referenceValue"`
}

func EqualsFactory(params json.RawMessage) (Policy, error) {
	var equals Equals
	err := json.Unmarshal(params, &equals)
	return &equals, err
}

func (p *Equals) CheckReport(ar *ar.AttestationReport) (ok bool, reason string, err error) {
	selector, ok := fieldSelectors[p.Field]
	if !ok {
		reason = fmt.Sprintf("Unknown attestation report field: %s.", p.Field)
		return
	}

	field := selector.Select(ar)
	if len(field) != len(p.ReferenceValue) {
		ok = false
		reason = fmt.Sprintf(
			"The reference data for %s has invalid length. Expected: %d, Got: %d.",
			p.Field,
			len(field),
			len(p.ReferenceValue),
		)
		return
	}

	if !bytes.Equal(field, p.ReferenceValue) {
		ok = false
		reason = fmt.Sprintf("The value of %s did not equal the reference value.", p.Field)
		return
	}

	ok = true
	return
}
