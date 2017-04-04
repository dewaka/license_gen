package lib

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
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

func (lic *LicenseData) UpdateKey(privKey string) error {
	jsonLicInfo, err := json.Marshal(lic.Info)
	if err != nil {
		return err
	}

	rsaPrivKey, err := ReadPrivateKey(privKey)
	if err != nil {
		return err
	}

	signedData, err := Sign(rsaPrivKey, jsonLicInfo)
	if err != nil {
		return err
	}

	lic.Key = base64.StdEncoding.EncodeToString(signedData)

	return nil
}

func (lic *LicenseData) ValidateKey(pubKey string) error {
	signedData, err := base64.StdEncoding.DecodeString(lic.Key)
	if err != nil {
		return err
	}

	// Now we need to check whether we can verify this data or not
	publicKey, err := ReadPublicKey(pubKey)
	if err != nil {
		return err
	}

	jsonLicInfo, err := json.Marshal(lic.Info)
	if err != nil {
		return err
	}

	if err := Unsign(publicKey, jsonLicInfo, signedData); err != nil {
		return err
	}

	fmt.Println("Successfully signed!")
	return nil
}

func (lic *LicenseData) SaveLicense(licName string) error {
	jsonLic, err := json.MarshalIndent(lic, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(licName, jsonLic, 0644)
}

func ReadLicense(licFile string) (*LicenseData, error) {
	ldata, err := ioutil.ReadFile(licFile)
	if err != nil {
		return nil, err
	}

	var license LicenseData
	if err := json.Unmarshal(ldata, &license); err != nil {
		return nil, err
	}

	return &license, nil
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

// Sign signs data with rsa-sha256
func Sign(r *rsa.PrivateKey, data []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, r, crypto.SHA256, d)
}

// Unsign verifies the message using a rsa-sha256 signature
func Unsign(r *rsa.PublicKey, message []byte, sig []byte) error {
	h := sha256.New()
	h.Write(message)
	d := h.Sum(nil)
	return rsa.VerifyPKCS1v15(r, crypto.SHA256, d, sig)
}

func TestLicensingLogic(privKey, pubKey string) error {
	fmt.Println("*** TestLicensingLogic ***")

	expDate := time.Date(2017, 7, 16, 0, 0, 0, 0, time.UTC)
	licInfo := LicenseInfo{Name: "Chathura Colombage", Expiration: expDate}

	jsonLicInfo, err := json.Marshal(licInfo)
	if err != nil {
		fmt.Println("Error marshalling json data:", err)
		return err
	}

	rsaPrivKey, err := ReadPrivateKey(privKey)
	if err != nil {
		fmt.Println("Error reading private key:", err)
		return err
	}

	signedData, err := Sign(rsaPrivKey, jsonLicInfo)
	if err != nil {
		fmt.Println("Error signing data:", err)
		return err
	}

	signedDataBase64 := base64.StdEncoding.EncodeToString(signedData)
	fmt.Println("Signed data:", signedDataBase64)

	// rsaPrivKey.Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts)

	// we need to sign jsonLicInfo using private key

	licData := LicenseData{Info: licInfo, Key: signedDataBase64}

	jsonLicData, err := json.MarshalIndent(licData, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling json data:", err)
		return err
	}

	fmt.Printf("License: \n%s\n", jsonLicData)

	backFromBase64, err := base64.StdEncoding.DecodeString(signedDataBase64)
	if err != nil {
		fmt.Println("Error decoding base64")
		return err
	}

	// Now we need to check whether we can verify this data or not
	publicKey, err := ReadPublicKey(pubKey)
	if err != nil {
		return err
	}

	if err := Unsign(publicKey, backFromBase64, signedData); err != nil {
		fmt.Println("Couldn't Sign!")
	}

	fmt.Println("Successfully signed!")

	return nil
}

func TestLicensing(privKey, pubKey string) error {
	fmt.Println("*** TestLicensingLogic ***")

	expDate := time.Date(2017, 7, 16, 0, 0, 0, 0, time.UTC)
	licInfo := LicenseInfo{Name: "Chathura Colombage", Expiration: expDate}
	licData := &LicenseData{Info: licInfo}

	if err := licData.UpdateKey(privKey); err != nil {
		fmt.Println("Couldn't update key")
		return err
	}

	fmt.Println("Key is:", licData.Key)

	if err := licData.ValidateKey(pubKey); err != nil {
		fmt.Println("Couldn't validate key")
		return err
	}

	fmt.Println("License is valid!")

	licData.Info.Name = "Chat Colombage"

	if err := licData.ValidateKey(pubKey); err != nil {
		fmt.Println("Couldn't validate key")
		return err
	}
	fmt.Println("License is still valid!")

	return nil
}
