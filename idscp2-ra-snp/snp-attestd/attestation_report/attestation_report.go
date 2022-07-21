package attestation_report

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"math/big"
)

// Attestation report structure
// This type reflects the AMD SEV-SNP attestation report as described in
// https://www.amd.com/system/files/TechDocs/56860.pdf, Table 21.
// Where applicable, the original field names are appended to each field using json tags.
// Adapted from:
// https://github.com/Fraunhofer-AISEC/cmc/blob/05cbe115e9edca9152e7d0ec305d70ef7c277803/attestationreport/snp.go
type AttestationReport struct {
	// Table 21 @ https://www.amd.com/system/files/TechDocs/56860.pdf
	Version         uint32   `json:"VERSION"`
	GuestSvn        uint32   `json:"GUEST_SVN"`
	Policy          uint64   `json:"POLICY"`
	FamilyId        [16]byte `json:"FAMILY_ID"`
	ImageId         [16]byte `json:"IMAGE_ID"`
	Vmpl            uint32   `json:"VMPL"`
	SignatureAlgo   uint32   `json:"SIGNATURE_ALGO"`
	CurrentTcb      uint64   `json:"CURRENT_TCB"` // platform_version
	PlatformInfo    uint64   `json:"PLATFORM_INFO"`
	AuthorKeyEn     uint32   `json:"AUTHOR_KEY_EN"`
	Reserved1       uint32
	ReportData      [64]byte `json:"REPORT_DATA"`
	Measurement     [48]byte `json:"MEASUREMENT"`
	HostData        [32]byte `json:"HOST_DATA"`
	IdKeyDigest     [48]byte `json:"ID_KEY_DIGEST"`
	AuthorKeyDigest [48]byte `json:"AUTHOR_KEY_DIGEST"`
	ReportId        [32]byte `json:"REPORT_ID"`
	ReportIdMa      [32]byte `json:"REPORT_ID_MA"`
	ReportedTcb     uint64   `json:"REPORTED_TCB"`
	Reserved2       [24]byte
	ChipId          [64]byte `json:"CHIP_ID"`
	//Reserved3 [192]byte
	CommittedTcb   uint64 `json:"COMMITTED_TCB"`
	CurrentBuild   uint8  `json:"CURRENT_BUILD"`
	CurrentMinor   uint8  `json:"CURRENT_MINOR"`
	CurrentMajor   uint8  `json:"CURRENT_MAJOR"`
	Reserved3a     uint8
	CommittedBuild uint8 `json:"COMMITTED_BUILD"`
	CommittedMinor uint8 `json:"COMMITTED_MINOR"`
	CommittedMajor uint8 `json:"COMMITTED_MAJOR"`
	Reserved3b     uint8
	LaunchTcb      uint64 `json:"LAUNCH_TCB"`
	Reserved3c     [168]byte
	// Table 23 @ https://www.amd.com/system/files/TechDocs/56860.pdf
	SignatureR [72]byte
	SignatureS [72]byte
	Reserved4  [368]byte
}

// Offset of the signature field in the attestation report according to
// https://www.amd.com/system/files/TechDocs/56860.pdf, Table 21
const signatureOffset = 0x2a0

// Verify the signature of an attestation report against a VCEK certificate.
// In order to avoid re-encoding the attestationn report, the raw report is also passed to this
// function.
func (a *AttestationReport) VerifySignature(rawReport []byte, vcekCert *x509.Certificate) (bool, error) {
	if len(rawReport) < signatureOffset {
		return false, fmt.Errorf("the data passed as the raw report is too small")
	}

	digest := sha512.Sum384(rawReport[:signatureOffset])

	// Verify, that the signature algorithm is supported
	// Currently, only ECDSA with curve P-384 and SHA-384 digest (value 1) is supported
	if a.SignatureAlgo != 1 {
		return false, fmt.Errorf("unknown or invalid signature algorithm: %d", a.SignatureAlgo)
	}

	// Convert bytes to usable BigInts

	// Golang SetBytes expects BigEndian byte array, but SNP values are little endian
	rRaw := a.SignatureR[:]
	for i := 0; i < len(rRaw)/2; i++ {
		rRaw[i], rRaw[len(rRaw)-i-1] = rRaw[len(rRaw)-i-1], rRaw[i]
	}
	sRaw := a.SignatureS[:]
	for i := 0; i < len(sRaw)/2; i++ {
		sRaw[i], sRaw[len(sRaw)-i-1] = sRaw[len(sRaw)-i-1], sRaw[i]
	}

	// Convert r, s to Big Int
	r := new(big.Int)
	r.SetBytes(rRaw)
	s := new(big.Int)
	s.SetBytes(sRaw)

	// Extract the public key from the certificate
	pub, ok := vcekCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("VCEK certificate has an incorrect public key format")
	}

	// Verify ECDSA Signature represented by r and s
	return ecdsa.Verify(pub, digest[:], r, s), nil
}
