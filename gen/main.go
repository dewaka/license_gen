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

var (
	typePtr = flag.String("type", "", "Operation type. Valid values are license or certificate.")
	licFile = flag.String("lic", "license.json", "License file name. Required for license generation.")
	certKey = flag.String("cert", "cert.pem", "Public certificate key.")
	privKey = flag.String("key", "key.pem", "Certificate key file. Required for license generation.")

	rsaBits = flag.Int("rsa-bits", 2048, "Size of RSA key to generate. Only used when type is certificate.")
)

func main() {
	flag.Parse()

	switch *typePtr {
	case "lic", "license":
		fmt.Println("Generating license")
		if err := generateLicense(); err != nil {
			fmt.Println("Error generating license:", err)
		}
	case "cert", "certificate":
		if err := generateCertificate(); err != nil {
			fmt.Fprintf(os.Stderr, "Certificate generation failed: %s\n", err)
			os.Exit(1)
		}
	case "test":
		hasError := false
		if _, err := lib.ReadPublicKeyFromFile("cert.pem"); err != nil {
			fmt.Println("Error reading public key:", err)
			hasError = true
		}

		if _, err := lib.ReadPrivateKeyFromFile("key.pem"); err != nil {
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

func generateLicense() error {
	expDate := time.Date(2017, 7, 16, 0, 0, 0, 0, time.UTC)
	licInfo := lib.LicenseInfo{Name: "Chathura Colombage", Expiration: expDate}
	licData := &lib.LicenseData{Info: licInfo}

	licData.UpdateKey(*privKey)

	return licData.SaveLicense(*licFile)
}
