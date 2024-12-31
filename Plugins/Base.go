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

// ReadBytes 从连接读取数据直到EOF或错误
func ReadBytes(conn net.Conn) ([]byte, error) {
	size := 4096 // 缓冲区大小
	buf := make([]byte, size)
	var result []byte
	var lastErr error

	// 循环读取数据
	for {
		count, err := conn.Read(buf)
		if err != nil {
			lastErr = err
			break
		}

		result = append(result, buf[0:count]...)

		// 如果读取的数据小于缓冲区,说明已经读完
		if count < size {
			break
		}
	}

	// 如果读到了数据,则忽略错误
	if len(result) > 0 {
		return result, nil
	}

	return result, lastErr
}

// 默认AES加密密钥
var key = "0123456789abcdef"

// AesEncrypt 使用AES-CBC模式加密字符串
func AesEncrypt(orig string, key string) (string, error) {
	// 转为字节数组
	origData := []byte(orig)
	keyBytes := []byte(key)

	// 创建加密块,要求密钥长度必须为16/24/32字节
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("创建加密块失败: %v", err)
	}

	// 获取块大小并填充数据
	blockSize := block.BlockSize()
	origData = PKCS7Padding(origData, blockSize)

	// 创建CBC加密模式
	blockMode := cipher.NewCBCEncrypter(block, keyBytes[:blockSize])

	// 加密数据
	encrypted := make([]byte, len(origData))
	blockMode.CryptBlocks(encrypted, origData)

	// base64编码
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// AesDecrypt 使用AES-CBC模式解密字符串
func AesDecrypt(crypted string, key string) (string, error) {
	// base64解码
	cryptedBytes, err := base64.StdEncoding.DecodeString(crypted)
	if err != nil {
		return "", fmt.Errorf("base64解码失败: %v", err)
	}

	keyBytes := []byte(key)

	// 创建解密块
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("创建解密块失败: %v", err)
	}

	// 创建CBC解密模式
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, keyBytes[:blockSize])

	// 解密数据
	origData := make([]byte, len(cryptedBytes))
	blockMode.CryptBlocks(origData, cryptedBytes)

	// 去除填充
	origData, err = PKCS7UnPadding(origData)
	if err != nil {
		return "", fmt.Errorf("去除PKCS7填充失败: %v", err)
	}

	return string(origData), nil
}

// PKCS7Padding 对数据进行PKCS7填充
func PKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// PKCS7UnPadding 去除PKCS7填充
func PKCS7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("数据长度为0")
	}

	padding := int(data[length-1])
	if padding > length {
		return nil, errors.New("填充长度无效")
	}

	return data[:length-padding], nil
}
