package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

// Config struct to hold configuration data
type Config struct {
	Username    string `yaml:"username"`
	ProductID   string `yaml:"product_id"`
	ExpiryDay   int    `yaml:"expiry_day"`
	Permissions string `yaml:"permissions"`
	Key         string `yaml:"key"`
}

// License struct to hold license information
type License struct {
	Username    string `json:"username"`
	ProductID   string `json:"product_id"`
	IssueDate   string `json:"issue_date"`
	ExpiryDate  string `json:"expiry_date"`
	Permissions string `json:"permissions"`
}

// GenerateLicense function to create an encrypted license string
func GenerateLicense(license License, key []byte) (string, error) {
	licenseData, err := json.Marshal(license)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(licenseData))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], licenseData)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func main() {
	// Read configuration from file
	configFile, err := os.Open("config.yaml")
	if err != nil {
		fmt.Println("Error opening config file:", err)
		return
	}
	defer configFile.Close()

	byteValue, err := ioutil.ReadAll(configFile)
	if err != nil {
		fmt.Println("Error reading config file:", err)
		return
	}

	var config Config
	err = yaml.Unmarshal(byteValue, &config)
	if err != nil {
		fmt.Println("Error parsing config file:", err)
		return
	}

	license := License{
		Username:  config.Username,
		ProductID: config.ProductID,
		IssueDate: time.Now().Format(time.RFC3339),
		// ExpiryDate:  time.Now().AddDate(0, 0, 7).Format(time.RFC3339),
		ExpiryDate:  time.Now().Add(time.Hour * 24 * time.Duration(config.ExpiryDay)).Format(time.RFC3339),
		Permissions: config.Permissions,
	}

	encryptionKey := []byte(config.Key) // Replace with your actual key
	encryptedLicense, err := GenerateLicense(license, encryptionKey)
	if err != nil {
		fmt.Println("Error generating license:", err)
		return
	}
	serializedLicense, err := json.Marshal(license)
	if err != nil {
		fmt.Println("Error marshaling license:", err)
		return
	}
	fmt.Println("Decrypted License:", string(serializedLicense))
	fmt.Println("Encrypted License:", encryptedLicense)
}
