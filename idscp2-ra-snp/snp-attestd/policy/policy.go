package policy

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"strings"

	ar "github.com/industrial-data-space/idscp2-rat-drivers/idscp2-ra-snp/snp-attestd/attestation_report"
)

// This object represents a policy implementation
type Policy interface {
	// Check whether the given attestation report conforms to the given policy.
	// If the check fails, a reason for failure should be provided.
	CheckReport(ar *ar.AttestationReport) (ok bool, reason string, err error)
}

// Get a field from the attestation report
type fieldSelector int

// Get the attestation report's field as specified by the field selector
func (f fieldSelector) Select(ar *ar.AttestationReport) []byte {
	reflectValue := reflect.ValueOf(*ar)
	value := reflectValue.Field(int(f)).Interface()
	var byteBuffer bytes.Buffer
	binary.Write(&byteBuffer, binary.LittleEndian, value)
	return byteBuffer.Bytes()
}

// Build a table of field selectors for the attestation report struct in
// "../attestation_report.go".
// This function uses reflection to iterate over the attestation report and builds a lookup
// function for each field that has a `json` tag.
// This way, only the type has to be kept in sync with the AMD docs while the lookup table updates
// automatically.
func buildFieldSelectorTable() map[string](fieldSelector) {
	reflectType := reflect.TypeOf(ar.AttestationReport{})
	result := make(map[string]fieldSelector)

	// Iterate through all fields in the attestation report
	for i := 0; i < reflectType.NumField(); i++ {
		field := reflectType.Field(i)
		// Skip the field if it does not have a fieldName tag
		// The fileName tag maps the go field to the field name given in
		// https://www.amd.com/system/files/TechDocs/56860.pdf, Table 21
		tag, ok := field.Tag.Lookup("json")
		if !ok {
			continue
		}

		// If someone added an extra argument to the json tag, make sure to only use the field name.
		fieldName, _, _ := strings.Cut(tag, ",")

		// Save the index of the field
		// This can later be used to obtain the field value from an attestation report
		result[fieldName] = fieldSelector(i)
	}

	return result
}

var fieldSelectors = buildFieldSelectorTable()
