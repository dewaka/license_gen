package main

import (
	"flag"
	"fmt"

	"github.com/dewaka/license_gen/lib"
)

var (
	licFile = flag.String("lic", "license.json", "License file name. Required for license generation.")
	certKey = flag.String("cert", "cert.pem", "Public certificate key.")
)

func main() {
	// fmt.Println("Hi there")
	// if err := lib.TestLicensing("key.pem", "cert.pem"); err != nil {
	// 	fmt.Println("Error licensing logic:", err)
	// 	os.Exit(1)
	// }

	// fmt.Println("Done!")

	checkLicense()
}

func checkLicense() error {
	license, err := lib.ReadLicense(*licFile)
	if err != nil {
		fmt.Println("Error:", err)
		return err
	}

	fmt.Println("Name:", license.Info.Name)
	fmt.Println("Expiry:", license.Info.Expiration)
	fmt.Println("Key:", license.Key)

	if err := license.ValidateKey(*certKey); err != nil {
		fmt.Println("License is not valid!")
		return err
	}

	fmt.Println("License is valid!")

	return nil
}
