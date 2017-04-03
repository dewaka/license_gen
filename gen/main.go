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
		fmt.Println("Generating license")
		if *filePtr == "" {
			fmt.Fprintf(os.Stderr, "License required for check")
		} else {
			lib.CheckLicenseFile(*filePtr)
		}
	case "cert", "certificate":
		fmt.Println("Generating license")
		testGenLicense()
	default:
		fmt.Fprintf(os.Stderr, "Invalid operation type: %s", *typePtr)
	}
}
