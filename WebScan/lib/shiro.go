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
	CheckContent = "rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFsQ29sbGVjdGlvbqh/WCXGowhKAwABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRpbC9NYXA7eHBwdwEAeA=="
	Content, _   = base64.StdEncoding.DecodeString(CheckContent)
)

func Padding(plainText []byte, blockSize int) []byte {
	//计算要填充的长度
	n := (blockSize - len(plainText)%blockSize)
	//对原来的明文填充n个n
	temp := bytes.Repeat([]byte{byte(n)}, n)
	plainText = append(plainText, temp...)
	return plainText
}

func GetShrioCookie(key, mode string) string {
	if mode == "gcm" {
		return AES_GCM_Encrypt(key)
	} else {
		//cbc
		return AES_CBC_Encrypt(key)
	}
}

//AES CBC加密后的payload
func AES_CBC_Encrypt(shirokey string) string {
	key, err := base64.StdEncoding.DecodeString(shirokey)
	if err != nil {
		return ""
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	Content = Padding(Content, block.BlockSize())
	iv := uuid.NewV4().Bytes()                     //指定初始向量vi,长度和block的块尺寸一致
	blockMode := cipher.NewCBCEncrypter(block, iv) //指定CBC分组模式，返回一个BlockMode接口对象
	cipherText := make([]byte, len(Content))
	blockMode.CryptBlocks(cipherText, Content) //加密数据
	return base64.StdEncoding.EncodeToString(append(iv[:], cipherText[:]...))
}

//AES GCM 加密后的payload shiro 1.4.2版本更换为了AES-GCM加密方式
func AES_GCM_Encrypt(shirokey string) string {
	key, err := base64.StdEncoding.DecodeString(shirokey)
	if err != nil {
		return ""
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	nonce := make([]byte, 16)
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return ""
	}
	aesgcm, _ := cipher.NewGCMWithNonceSize(block, 16)
	ciphertext := aesgcm.Seal(nil, nonce, Content, nil)
	return base64.StdEncoding.EncodeToString(append(nonce, ciphertext...))
}
