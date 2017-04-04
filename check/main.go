package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/dewaka/license_gen/lib"
)

var (
	licFile = flag.String("lic", "license.json", "License file name. Required for license generation.")
	certKey = flag.String("cert", "cert.pem", "Public certificate key.")
	verbose = flag.Bool("verbose", false, "Print verbose messages")
)

func main() {
	flag.Parse()

	if err := checkLicense(*verbose); err != nil {
		fmt.Fprintf(os.Stderr, "License check failed: %s", err)
		os.Exit(1)
	}

	fmt.Println("License OK")
}

func checkLicense(verbose bool) error {
	license, err := lib.ReadLicenseFromFile(*licFile)
	if err != nil {
		return fmt.Errorf("Read License failed: %s\n", err)
	}

	if verbose {
		fmt.Println("Name:", license.Info.Name)
		fmt.Println("Expiry:", license.Info.Expiration)
		fmt.Println("Key:", license.Key)
	}

	if err := license.ValidateLicenseKey(*certKey); err != nil {
		return fmt.Errorf("Invalid license: %s", err)
	}

	return nil
}
