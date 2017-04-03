package lib

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

type PrivateKey *rsa.PrivateKey

// LicenseInfo - Core information about a license
type LicenseInfo struct {
	Name       string    `json:"name"`
	Expiration time.Time `json:"expiration"`
}

// LicenseData - This is the license data we serialise into a license file
type LicenseData struct {
	Info LicenseInfo `json:"info"`
	Key  string      `json:"key"`
}

// License check error codes
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

func GenKey(len int) (PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, len)
	return PrivateKey(key), err
}

func GenLicenseFile(info *LicenseInfo, key PrivateKey, w io.Writer) bool {
	fmt.Fprintf(w, "New license to %s, expiring on: %s", info.Name, info.Expiration)

	licenseData := LicenseData{Info: *info}
	licenseData.Key = "<signed key>"

	licData, _ := json.Marshal(licenseData)
	fmt.Fprintln(w, string(licData))

	return true
}

func TestEncryption() {
	key, err := GenKey(2048)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	msg := []byte("show must go on")
	label := []byte("")
	hash := sha256.New()

	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, &key.PublicKey, msg, label)
	if err != nil {
		fmt.Println("Failed to encrypt:", err)
		return
	}

	fmt.Printf("OAEP encrypted [%s] to \n[%x]\n", string(msg), ciphertext)
}

func TestSigning() {
	key, err := GenKey(2048)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	msg := []byte("show must go on")

	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto
	PSSmessage := msg

	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(PSSmessage)
	hashed := pssh.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, key, newhash, hashed, &opts)

	if err != nil {
		fmt.Println("Error creating signature:", err)
		return
	}

	fmt.Printf("PSS Signature : %x\n", signature)

	if err := rsa.VerifyPSS(&key.PublicKey, newhash, hashed, signature, &opts); err != nil {
		fmt.Println("error verifying:", err)
	} else {
		fmt.Println("Verified!")
	}

	fmt.Println("Verified Signature!")
}

func CheckLicenseFile(licenseFile string) int {
	return Error
}
