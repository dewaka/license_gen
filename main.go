package main

import (
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

func genCheckLicense() {
	info := &lib.LiceseInfo{
		Name:       "Chathura",
		Expiration: time.Date(2017, time.July, 16, 0, 0, 0, 0, time.UTC),
	}

	switch status := lib.CheckLicense(info, "test.lic"); status {
	case lib.Valid:
		fmt.Println("Ok")
	default:
		fmt.Println("License check failed:", status)
	}
}

func testGenLicense() {
	key, err := lib.GenKey(2048)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	info := &lib.LiceseInfo{
		Name:       "Chathura",
		Expiration: time.Date(2017, time.July, 16, 0, 0, 0, 0, time.UTC),
	}

	lib.GenLicense(info, key, os.Stdout)
}

func main() {
	// testGenKey()
	// testGenLicense()
	// lib.TestEncryption()
	lib.TestSigning()
}
