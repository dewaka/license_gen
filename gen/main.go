package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/dewaka/license_gen/lib"
)

func testGenKey() {
	key, err := lib.GenKey(2048)
	if err != nil {
		fmt.Println("Error generating key!")
		return
	}

	fmt.Println("Public Key: ", key.PublicKey)
	fmt.Println("Private Key: ", key)

}

func testGenLicense() {
	key, err := lib.GenKey(2048)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	info := &lib.LicenseInfo{
		Name:       "Chathura",
		Expiration: time.Date(2017, time.July, 16, 0, 0, 0, 0, time.UTC),
	}

	lib.GenLicenseFile(info, key, os.Stdout)
}

var (
	typePtr = flag.String("type", "", "Operation type. Valid values are license or certificate.")
	filePtr = flag.String("file", "", "File name - for either license or certificate.")
	keyPtr  = flag.String("key", "", "Certificate key file. Only required if the type is license.")
	rsaBits = flag.Int("rsa-bits", 2048, "Size of RSA key to generate. Only used when type is certificate.")
)

func main() {
	flag.Parse()

	fmt.Println("type:", *typePtr)
	fmt.Println("file:", *filePtr)
	fmt.Println("key:", *keyPtr)
	fmt.Println("rsaBits:", *rsaBits)
	fmt.Println("tail:", flag.Args())

	switch *typePtr {
	case "lic", "license":
		if *filePtr == "" {
			fmt.Fprintf(os.Stderr, "Certificate required for license generation\n")
			os.Exit(1)
		} else {
			fmt.Println("Generating license")
			testGenLicense()
		}
	case "cert", "certificate":
		if err := generateCertificate(); err != nil {
			fmt.Fprintf(os.Stderr, "Certificate generation failed: %s\n", err)
			os.Exit(1)
		}
	case "test":
		hasError := false
		if err := lib.TestReadPublicKey(); err != nil {
			fmt.Println("Error reading public key:", err)
			hasError = true
		}

		if err := lib.TestReadPrivateKey(); err != nil {
			fmt.Println("Error reading private key:", err)
			hasError = true
		}

		if hasError {
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Invalid operation type: %s", *typePtr)
		os.Exit(1)
	}
}

func generateCertificate() error {
	fmt.Println("Generating x509 Certificate")
	return lib.GenerateCertificate("cert.pem", "key.pem", *rsaBits)
}
