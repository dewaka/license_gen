package lib

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"runtime"
	"time"
)

// License check errors
var (
	ErrorLicenseRead    = errors.New("Could not read license")
	ErrorPrivKeyRead    = errors.New("Could not read private key")
	ErrorPubKeyRead     = errors.New("Could not read public key")
	InvalidLicense      = errors.New("Invalid License file")
	ExpiredLicense      = errors.New("License expired")
	UnsupportedPlatform = errors.New("License does not support current platform")
)

// LicenseInfo - Core information about a license
type LicenseInfo struct {
	Name       string    `json:"name"`
	Platforms  []string  `json:"platforms"`
	Expiration time.Time `json:"expiration"`
}

// LicenseData - This is the license data we serialise into a license file
type LicenseData struct {
	Info LicenseInfo `json:"info"`
	Key  string      `json:"key"`
}

// NewLicense from given info
func NewLicense(name string, expiry time.Time, platforms []string) *LicenseData {
	return &LicenseData{Info: LicenseInfo{Name: name, Platforms: platforms, Expiration: expiry}}
}

func encodeKey(keyData []byte) string {
	return base64.StdEncoding.EncodeToString(keyData)
}

func decodeKey(keyStr string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(keyStr)
}

// Sign the License by updating the LicenseData.Key with given RSA private key
func (lic *LicenseData) Sign(pkey *rsa.PrivateKey) error {
	jsonLicInfo, err := json.Marshal(lic.Info)
	if err != nil {
		return err
	}

	signedData, err := Sign(pkey, jsonLicInfo)
	if err != nil {
		return err
	}

	lic.Key = encodeKey(signedData)

	return nil
}

// SignWithKey signs the License by updating the LicenseData.Key with given RSA
// private key read from a file
func (lic *LicenseData) SignWithKey(privKey string) error {
	rsaPrivKey, err := ReadPrivateKeyFromFile(privKey)
	if err != nil {
		return err
	}

	return lic.Sign(rsaPrivKey)
}

func (lic *LicenseData) ValidateLicenseKeyWithPublicKey(publicKey *rsa.PublicKey) error {
	signedData, err := decodeKey(lic.Key)
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

	return nil
}

func (lic *LicenseData) ValidateLicenseKey(pubKey string) error {
	publicKey, err := ReadPublicKeyFromFile(pubKey)
	if err != nil {
		return err
	}

	return lic.ValidateLicenseKeyWithPublicKey(publicKey)
}

// CheckLicenseInfo checks license for logical errors such as for license expiry
func (lic *LicenseData) CheckLicenseInfo() error {
	// Check validity of expiration date
	if time.Now().After(lic.Info.Expiration) {
		return ExpiredLicense
	}

	// Check validity of platform

	platformOk := false
	currentPlatform := runtime.GOOS
	for _, p := range lic.Info.Platforms {
		if p == currentPlatform {
			platformOk = true
			break
		}
	}

	if !platformOk {
		return UnsupportedPlatform
	}

	return nil
}

func (lic *LicenseData) WriteLicense(w io.Writer) error {
	jsonLic, err := json.MarshalIndent(lic, "", "  ")
	if err != nil {
		return err
	}

	_, werr := fmt.Fprintf(w, "%s", string(jsonLic))
	return werr
}

func (lic *LicenseData) SaveLicenseToFile(licName string) error {
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

// TODO: Move this to a proper test
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

	return nil
}

func TestLicensing(privKey, pubKey string) error {
	fmt.Println("*** TestLicensingLogic ***")

	expDate := time.Date(2017, 7, 16, 0, 0, 0, 0, time.UTC)
	licInfo := LicenseInfo{Name: "Chathura Colombage", Expiration: expDate}
	licData := &LicenseData{Info: licInfo}

	if err := licData.SignWithKey(privKey); err != nil {
		fmt.Println("Couldn't update key")
		return err
	}

	fmt.Println("Key is:", licData.Key)

	if err := licData.ValidateLicenseKey(pubKey); err != nil {
		fmt.Println("Couldn't validate key")
		return err
	}

	fmt.Println("License is valid!")

	licData.Info.Name = "Chat Colombage"

	if err := licData.ValidateLicenseKey(pubKey); err != nil {
		fmt.Println("Couldn't validate key")
		return err
	}
	fmt.Println("License is still valid!")

	return nil
}

// CheckLicenseFile reads a license from lr and then validate it against the
// public key read from pkr
func CheckLicense(lr, pkr io.Reader) error {
	lic, err := ReadLicense(lr)
	if err != nil {
		return ErrorLicenseRead
	}

	publicKey, err := ReadPublicKey(pkr)
	if err != nil {
		return ErrorPubKeyRead
	}

	if err := lic.ValidateLicenseKeyWithPublicKey(publicKey); err != nil {
		return InvalidLicense // we have a key mismatch here meaning license data is tampered
	}

	return lic.CheckLicenseInfo()
}
