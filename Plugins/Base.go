package Plugins

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
)

// ReadBytes reads data from the connection until EOF or error
func ReadBytes(conn net.Conn) ([]byte, error) {
	size := 4096 // Buffer size
	buf := make([]byte, size)
	var result []byte
	var lastErr error

	// Loop to read data
	for {
		count, err := conn.Read(buf)
		if (err != nil) {
			lastErr = err
			break
		}

		result = append(result, buf[0:count]...)

		// If the read data is less than the buffer size, it means it has been read completely
		if count < size {
			break
		}
	}

	// If data is read, ignore the error
	if len(result) > 0 {
		return result, nil
	}

	return result, lastErr
}

// Default AES encryption key
var key = "0123456789abcdef"

// AesEncrypt encrypts a string using AES-CBC mode
func AesEncrypt(orig string, key string) (string, error) {
	// Convert to byte array
	origData := []byte(orig)
	keyBytes := []byte(key)

	// Create encryption block, the key length must be 16/24/32 bytes
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("Failed to create encryption block: %v", err)
	}

	// Get block size and pad data
	blockSize := block.BlockSize()
	origData = PKCS7Padding(origData, blockSize)

	// Create CBC encryption mode
	blockMode := cipher.NewCBCEncrypter(block, keyBytes[:blockSize])

	// Encrypt data
	encrypted := make([]byte, len(origData))
	blockMode.CryptBlocks(encrypted, origData)

	// Base64 encode
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// AesDecrypt decrypts a string using AES-CBC mode
func AesDecrypt(crypted string, key string) (string, error) {
	// Base64 decode
	cryptedBytes, err := base64.StdEncoding.DecodeString(crypted)
	if err != nil {
		return "", fmt.Errorf("Failed to base64 decode: %v", err)
	}

	keyBytes := []byte(key)

	// Create decryption block
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("Failed to create decryption block: %v", err)
	}

	// Create CBC decryption mode
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, keyBytes[:blockSize])

	// Decrypt data
	origData := make([]byte, len(cryptedBytes))
	blockMode.CryptBlocks(origData, cryptedBytes)

	// Remove padding
	origData, err = PKCS7UnPadding(origData)
	if err != nil {
		return "", fmt.Errorf("Failed to remove PKCS7 padding: %v", err)
	}

	return string(origData), nil
}

// PKCS7Padding pads data using PKCS7
func PKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// PKCS7UnPadding removes PKCS7 padding
func PKCS7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("Data length is 0")
	}

	padding := int(data[length-1])
	if padding > length {
		return nil, errors.New("Invalid padding length")
	}

	return data[:length-padding], nil
}
