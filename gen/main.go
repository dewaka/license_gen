package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/dewaka/license_gen/lib"
)

var (
	typePtr = flag.String("type", "", "Operation type. Valid values are license or certificate.")
	licFile = flag.String("lic", "license.json", "License file name. Required for license generation.")
	certKey = flag.String("cert", "cert.pem", "Public certificate key.")
	privKey = flag.String("key", "key.pem", "Certificate key file. Required for license generation.")
	rsaBits = flag.Int("rsa-bits", 2048, "Size of RSA key to generate. Only used when type is certificate.")

	// Required info for license generation
	name      = flag.String("name", "", "Name of the Licensee")
	expDate   = flag.String("expiry", "", "Expiry date for the License. Expected format is 2006-1-02")
	platforms = flag.String("platforms", "linux,darwin,windows", "Comma separated list of platforms the license supports")

	verbose = flag.Bool("verbose", true, "Print verbose messages")
)

func printPlatform() {
	fmt.Println("Runtime:", runtime.GOOS)
}

func main() {
	flag.Parse()

	printPlatform()

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
		fmt.Fprintf(os.Stderr, "Invalid operation type: '%s'\n", *typePtr)
		os.Exit(1)
	}
}

func generateCertificate() error {
	fmt.Println("Generating x509 Certificate")
	return lib.GenerateCertificate("cert.pem", "key.pem", *rsaBits)
}

func generateLicense() error {
	if len(*name) == 0 {
		return fmt.Errorf("Licensee name is empty")
	}

	date, err := time.Parse("2006-1-02", *expDate)
	if err != nil {
		return err
	}

	supPlatforms := strings.Split(*platforms, ",")
	lic := lib.NewLicense(*name, date, supPlatforms)

	if *verbose {
		fmt.Println("Licensee:", *name)
		fmt.Printf("Platforms: %v\n", supPlatforms)
		fmt.Println("Expiry date:", date)
		fmt.Println("Signing with private key:", *privKey)
	}

	if err := lic.SignWithKey(*privKey); err != nil {
		return err
	}

	if *verbose {
		fmt.Println("Signing OK. Saving License to:", *licFile)
		fmt.Println("*** BEGIN LICENSE ***")
		lic.WriteLicense(os.Stdout)
		fmt.Println("\n*** END LICENSE ***")
	}

	return lic.SaveLicenseToFile(*licFile)
}
