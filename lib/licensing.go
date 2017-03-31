package lib

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"time"
)

type PrivateKey *rsa.PrivateKey

type LiceseInfo struct {
	Name       string
	Expiration time.Time
}

const (
	Error   = iota // io or other type of error computing with keys
	Invalid        // signature mismatch error (invalid license)
	Expired        // license is valid, but expired now
	Valid          // valid non-expired license
)

func privateKeyStuff() error {

	jimenaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		return err
	}

	jimenaPublicKey := &jimenaPrivateKey.PublicKey

	alistairPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		return err
	}

	alistairPublicKey := &alistairPrivateKey.PublicKey

	fmt.Println("Private Key : ", jimenaPrivateKey)
	fmt.Println("Public key ", jimenaPublicKey)
	fmt.Println("Private Key : ", alistairPrivateKey)
	fmt.Println("Public key ", alistairPublicKey)

	return nil
}

func CheckLicense(info *LiceseInfo, file string) int {
	fmt.Println("Checking License for", info.Name)

	// if err := privateKeyStuff(); err != nil {
	// 	fmt.Fprintf(os.Stderr, "Error: %s", err)
	// 	return false
	// }

	return Valid
}

func GenKey(len int) (PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, len)
	return PrivateKey(key), err
}

func GenLicense(info *LiceseInfo, key PrivateKey, w io.Writer) bool {
	fmt.Fprintf(w, "New license to %s, expiring on: %s", info.Name, info.Expiration)
	return true
}
