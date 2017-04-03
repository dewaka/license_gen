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
	opPtr   = flag.String("op", "", "Operation type. Valid values are check, gen-lic, and gen-cert")
	licPtr  = flag.String("lic", "", "license file")
	keyPtr  = flag.String("key", "", "key file")
	rsaBits = flag.Int("rsa-bits", 2048, "Size of RSA key to generate")
)

func main() {
	flag.Parse()

	fmt.Println("op:", *opPtr)
	fmt.Println("lic:", *licPtr)
	fmt.Println("key:", *keyPtr)
	fmt.Println("rsaBits:", *rsaBits)
	fmt.Println("tail:", flag.Args())

	switch *opPtr {
	case "check":
		fmt.Println("Checking license")
		if *licPtr == "" {
			fmt.Fprintf(os.Stderr, "License required for check")
		} else {
			lib.CheckLicenseFile(*licPtr)
		}
	case "gen-lic":
		fmt.Println("Generating license")
		testGenLicense()
	case "gen-cert":
		fmt.Println("Generating certificate")
		// lib.GenerateCertificate()
	default:
		fmt.Fprintf(os.Stderr, "Invalid operation: %s", *opPtr)
	}
}
