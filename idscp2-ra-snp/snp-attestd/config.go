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
	// This is usefull when the SNP guest device is not available.
	VerifyOnly bool
}
