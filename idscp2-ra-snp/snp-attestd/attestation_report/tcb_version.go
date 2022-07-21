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
