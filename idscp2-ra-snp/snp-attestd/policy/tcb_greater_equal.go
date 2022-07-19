package policy

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	ar "github.com/industrial-data-space/idscp2-rat-drivers/idscp2-ra-snp/snp-attestd/attestation_report"
)

type TcbGreaterEqual struct {
	Field         string `json:"field"`
	MinBootloader uint8  `json:"minBootloaderVersion"`
	MinTEE        uint8  `json:"minTEEVersion"`
	MinSNP        uint8  `json:"minSNPVersion"`
	MinMicrocode  uint8  `json:"minMicrocodeVersion"`
}

func TcbGreaterEqualFactory(params json.RawMessage) (Policy, error) {
	var tcbGreaterEqual TcbGreaterEqual
	err := json.Unmarshal(params, &tcbGreaterEqual)
	return &tcbGreaterEqual, err
}

func (p *TcbGreaterEqual) CheckReport(report *ar.AttestationReport) (ok bool, reason string, err error) {
	selector, ok := fieldSelectors[p.Field]
	if !ok {
		reason = fmt.Sprintf("Unknown attestation report field: %s.", p.Field)
		return
	}

	field := selector.Select(report)
	if len(field) != 8 {
		ok = false
		reason = fmt.Sprintf(
			"The field %s has incorrect length: %d. Is it a TCB version?",
			p.Field,
			len(field),
		)
		return
	}

	rawTcb := binary.LittleEndian.Uint64(field)
	tcb := ar.DecodeTcbVersion(rawTcb)

	if tcb.BootLoader < p.MinBootloader {
		ok = false
		reason = fmt.Sprintf(
			"The boot loader version %d is less than the allowed minimum of %d",
			tcb.BootLoader,
			p.MinBootloader,
		)
		return
	}

	if tcb.Tee < p.MinTEE {
		ok = false
		reason = fmt.Sprintf(
			"The TEE version %d is less than the allowed minimum of %d",
			tcb.Tee,
			p.MinTEE,
		)
		return
	}

	if tcb.Snp < p.MinSNP {
		ok = false
		reason = fmt.Sprintf(
			"The SNP version %d is less than the allowed minimum of %d",
			tcb.Snp,
			p.MinSNP,
		)
		return
	}

	if tcb.Microcode < p.MinMicrocode {
		ok = false
		reason = fmt.Sprintf(
			"The microcode version %d is less than the allowed minimum of %d",
			tcb.Microcode,
			p.MinMicrocode,
		)
		return
	}

	ok = true
	return
}
