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
	"os"
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

func encodeKey(keyData []byte) string {
	return base64.StdEncoding.EncodeToString(keyData)
}

func decodeKey(keyStr string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(keyStr)
}

func (lic *LicenseData) UpdateKey(privKey string) error {
	jsonLicInfo, err := json.Marshal(lic.Info)
	if err != nil {
		return err
	}

	rsaPrivKey, err := ReadPrivateKeyFromFile(privKey)
	if err != nil {
		return err
	}

	signedData, err := Sign(rsaPrivKey, jsonLicInfo)
	if err != nil {
		return err
	}

	lic.Key = encodeKey(signedData)

	return nil
}

func (lic *LicenseData) ValidateKey(pubKey string) error {
	signedData, err := decodeKey(lic.Key)
	if err != nil {
		return err
	}

	// Now we need to check whether we can verify this data or not
	publicKey, err := ReadPublicKeyFromFile(pubKey)
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

func ReadLicense(r io.Reader) (*LicenseData, error) {
	ldata, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var license LicenseData
	if err := json.Unmarshal(ldata, &license); err != nil {
		return nil, err
	}

	return &license, nil
}

func ReadLicenseFromFile(licFile string) (*LicenseData, error) {
	file, err := os.Open(licFile)
	defer file.Close()
	if err != nil {
		return nil, err
	}

	return ReadLicense(file)
}

// License check error codes
const (
	Error   = iota // io or other type of error computing with keys
	Invalid        // signature mismatch error (invalid license)
	Expired        // license is valid, but expired now
	Valid          // valid non-expired license
)

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

	rsaPrivKey, err := ReadPrivateKeyFromFile(privKey)
	if err != nil {
		fmt.Println("Error reading private key:", err)
		return err
	}

	signedData, err := Sign(rsaPrivKey, jsonLicInfo)
	if err != nil {
		fmt.Println("Error signing data:", err)
		return err
	}

	signedDataBase64 := encodeKey(signedData)
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

	backFromBase64, err := decodeKey(signedDataBase64)
	if err != nil {
		fmt.Println("Error decoding base64")
		return err
	}

	// Now we need to check whether we can verify this data or not
	publicKey, err := ReadPublicKeyFromFile(pubKey)
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

func CheckLicenseFile(licenseFile string) int {
	return Error
}
