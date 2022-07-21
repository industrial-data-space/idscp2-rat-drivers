package main

import (
	"log"
	"os"
	"path"

	lib "github.com/industrial-data-space/idscp2-rat-drivers/idscp2-ra-snp/snp-attestd"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s <targetDir>\n", os.Args[0])
	}

	targetDir := os.Args[1]

	ask, ark, err := lib.FetchVcekCertChain()
	if err != nil {
		log.Fatalf("Error fetching the VCEK certificate chain: %v", err)
	}

	err = os.WriteFile(path.Join(targetDir, "ask.crt"), ask, 0644)
	if err != nil {
		log.Fatalf("Could not write to the ASK's certificate file: %v", err)
	}

	err = os.WriteFile(path.Join(targetDir, "ark.crt"), ark, 0644)
	if err != nil {
		log.Fatalf("Could not write to the ARK's certificate file: %v", err)
	}
}
