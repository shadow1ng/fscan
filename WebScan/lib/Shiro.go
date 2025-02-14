package lib

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"

	uuid "github.com/satori/go.uuid"
)

var (
	// CheckContent 是经过base64编码的Shiro序列化对象
	CheckContent = "rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFsQ29sbGVjdGlvbqh/WCXGowhKAwABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRpbC9NYXA7eHBwdwEAeA=="
	// Content 是解码后的原始内容
	Content, _ = base64.StdEncoding.DecodeString(CheckContent)
)

// Padding 对明文进行PKCS7填充
func Padding(plainText []byte, blockSize int) []byte {
	// 计算需要填充的长度
	paddingLength := blockSize - len(plainText)%blockSize

	// 使用paddingLength个paddingLength值进行填充
	paddingText := bytes.Repeat([]byte{byte(paddingLength)}, paddingLength)

	return append(plainText, paddingText...)
}

// GetShrioCookie 获取加密后的Shiro Cookie值
func GetShrioCookie(key, mode string) string {
	if mode == "gcm" {
		return AES_GCM_Encrypt(key)
	}
	return AES_CBC_Encrypt(key)
}

// AES_CBC_Encrypt 使用AES-CBC模式加密
func AES_CBC_Encrypt(shirokey string) string {
	// 解码密钥
	key, err := base64.StdEncoding.DecodeString(shirokey)
	if err != nil {
		return ""
	}

	// 创建AES加密器
	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}

	// PKCS7填充
	paddedContent := Padding(Content, block.BlockSize())

	// 生成随机IV
	iv := uuid.NewV4().Bytes()

	// 创建CBC加密器
	blockMode := cipher.NewCBCEncrypter(block, iv)

	// 加密数据
	cipherText := make([]byte, len(paddedContent))
	blockMode.CryptBlocks(cipherText, paddedContent)

	// 拼接IV和密文并base64编码
	return base64.StdEncoding.EncodeToString(append(iv, cipherText...))
}

// AES_GCM_Encrypt 使用AES-GCM模式加密(Shiro 1.4.2+)
func AES_GCM_Encrypt(shirokey string) string {
	// 解码密钥
	key, err := base64.StdEncoding.DecodeString(shirokey)
	if err != nil {
		return ""
	}

	// 创建AES加密器
	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}

	// 生成16字节随机数作为nonce
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return ""
	}

	// 创建GCM加密器
	aesgcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return ""
	}

	// 加密数据
	ciphertext := aesgcm.Seal(nil, nonce, Content, nil)

	// 拼接nonce和密文并base64编码
	return base64.StdEncoding.EncodeToString(append(nonce, ciphertext...))
}
