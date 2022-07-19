package snp_attestd

type Config struct {
	// Path for the SNP guest device.
	SevDevice string
	// Cache directory to write the VCEK certificate to.
	CacheDir string
	// Only accept verify requests.
	// This is usefull when the SNP guest device is not available.
	VerifyOnly bool
}
