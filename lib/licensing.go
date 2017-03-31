package lib

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"time"
)

type LiceseInfo struct {
	Name       string
	Expiration time.Time
}

func privateKeyStuff() {

	jimenaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		fmt.Println(err.Error)
		os.Exit(1)
	}

	jimenaPublicKey := &jimenaPrivateKey.PublicKey

	alistairPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		fmt.Println("error:", err.Error)
		os.Exit(1)
	}

	alistairPublicKey := &alistairPrivateKey.PublicKey

	fmt.Println("Private Key : ", jimenaPrivateKey)
	fmt.Println("Public key ", jimenaPublicKey)
	fmt.Println("Private Key : ", alistairPrivateKey)
	fmt.Println("Public key ", alistairPublicKey)
}

func CheckLicense(info *LiceseInfo, file string) bool {
	fmt.Println("Checking License for", info.Name)
	privateKeyStuff()
	return true
}

func GenLicense(info *LiceseInfo, file string) bool {
	return false
}
