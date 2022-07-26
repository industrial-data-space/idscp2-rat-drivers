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
package snp_attestd

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	ar "github.com/industrial-data-space/idscp2-rat-drivers/idscp2-ra-snp/snp-attestd/attestation_report"
)

const (
	kdcBaseUrl   = "https://kdsintf.amd.com"
	vcekBaseUrl  = kdcBaseUrl + "/vcek/v1/Milan"
	certChainUrl = vcekBaseUrl + "/cert_chain"

	// Known vcek certificate extensions
	// as per https://www.amd.com/system/files/TechDocs/57230.pdf, Chapter 3
	microcodeOID  = "1.3.6.1.4.1.3704.1.3.8"
	snpOID        = "1.3.6.1.4.1.3704.1.3.3"
	teeOID        = "1.3.6.1.4.1.3704.1.3.2"
	bootLoaderOID = "1.3.6.1.4.1.3704.1.3.1"
	hwidOID       = "1.3.6.1.4.1.3704.1.4"

	// Maximum number of tries when retreiving VCEK certificates from AMD
	// Needed as the KDC only allows one request per IP every 10 seconds
	// With this value, snp-attestd will try to get certificates for one minute before aborting
	maxTries = 6
)

// Fetch the VCEK certificate for the given attestation report.
// The certificate is used to verify the signature of the report.
// As the AMD KDC only allows one request every 10 seconds, the return value of this function
// should be cached.
func FetchVcekCertForReport(report ar.AttestationReport) ([]byte, error) {
	chipId := hex.EncodeToString(report.ChipId[:])
	tcb := ar.DecodeTcbVersion(report.ReportedTcb)

	vcekUrl := fmt.Sprintf(
		"%s/%s?blSPL=%d&teeSPL=%d&snpSPL=%d&ucodeSPL=%d",
		vcekBaseUrl, chipId, tcb.BootLoader,
		tcb.Tee, tcb.Snp, tcb.Microcode,
	)

	for try := 1; try <= maxTries; try++ {
		resp, err := http.Get(vcekUrl)
		if err != nil {
			return []byte{}, fmt.Errorf("error performing HTTP request: %w", err)
		}
		switch resp.StatusCode {
		case 200:
			// Success: do nothing
		case 429:
			// Too manny requests: Sleep for 10 seconds and try again
			time.Sleep(time.Second * 10)
			continue
		default:
			return []byte{}, fmt.Errorf("the HTTP request returned an error: %s", resp.Status)
		}

		content, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return []byte{}, fmt.Errorf("could not read response from AMD KDS: %w", err)
		}

		return content, nil
	}

	return []byte{}, fmt.Errorf("maximum number of attempts exceeded")
}

// Verify the certificate extensions of the VCEK certificate.
// Each VCEK certificate contains extensions matching the chip ID and reported TCB versions of
// the corresponding attestation report.
func VerifyVcekCertificateExtensions(vcekCert *x509.Certificate, report ar.AttestationReport) bool {
	knownExtensions := make(map[string]interface{}, 5)
	tcb := ar.DecodeTcbVersion(report.ReportedTcb)

	// Populate known extensions
	knownExtensions[microcodeOID] = tcb.Microcode
	knownExtensions[snpOID] = tcb.Snp
	knownExtensions[teeOID] = tcb.Tee
	knownExtensions[microcodeOID] = tcb.Microcode
	knownExtensions[hwidOID] = report.ChipId[:]

	for _, ext := range vcekCert.Extensions {
		if val, exists := knownExtensions[ext.Id.String()]; exists {
			// Special case as the reference value is not an u8
			if ext.Id.String() == hwidOID {
				if !bytes.Equal(ext.Value, val.([]byte)) {
					return false
				}
				continue
			}

			// Adapted from
			// https://github.com/Fraunhofer-AISEC/cmc/blob/b73f28e01e59e58a239c5d18cbbaa8d3808e6358/attestationreport/attestationreport.go#L1136
			if len(ext.Value) != 3 {
				return false
			}
			if ext.Value[0] != 0x2 {
				return false
			}
			if ext.Value[1] != 0x1 {
				return false
			}
			if ext.Value[2] != val.(uint8) {
				return false
			}
		}
	}

	return true
}

// Fetch the VCEK certificate chain from the AMD KDC.
// The chain consists of the AMD Signing Key (ASK) and the AMD Root Key (ARK).
// Each VCEK is signed by the ASK, which is in turn signed by the ARK.
func FetchVcekCertChain() (askCert []byte, arkCert []byte, err error) {
	resp, err := http.Get(certChainUrl)
	if err != nil {
		err = fmt.Errorf("failed to perform http request to AMD KDC: %w", err)
		return
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("the HTTP request returned an error: %s", resp.Status)
		return
	}

	content, err := ioutil.ReadAll(resp.Body)

	askBlock, content := pem.Decode(content)
	if askBlock == nil {
		err = fmt.Errorf("failed to decode pem data received from the AMD KDC")
		return
	}

	if askBlock.Type != "CERTIFICATE" {
		err = fmt.Errorf("returned data is not a certificate")
		return
	}

	askCert = askBlock.Bytes

	arkBlock, content := pem.Decode(content)
	if arkBlock == nil {
		err = fmt.Errorf("failed to decode pem data received from the AMD KDC")
		return
	}

	if len(content) != 0 {
		log.Printf("The certificate chain response from the AMD KDC contains unexpected additional data")
	}

	if arkBlock.Type != "CERTIFICATE" {
		err = fmt.Errorf("returned data is not a certificate")
		return
	}

	arkCert = arkBlock.Bytes
	return
}
