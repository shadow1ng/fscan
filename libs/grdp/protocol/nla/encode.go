package nla

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"strings"

	"github.com/shadow1ng/fscan/libs/grdp/core"
	"golang.org/x/crypto/md4"
)

func MD4(data []byte) []byte {
	h := md4.New()
	h.Write(data)
	return h.Sum(nil)
}

func MD5(data []byte) []byte {
	h := md5.New()
	h.Write(data)
	return h.Sum(nil)
}

func HMAC_MD5(key, data []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// Version 2 of NTLM hash function
func NTOWFv2(password, user, domain string) []byte {
	return HMAC_MD5(MD4(core.UnicodeEncode(password)), core.UnicodeEncode(strings.ToUpper(user)+domain))
}

// Same as NTOWFv2
func LMOWFv2(password, user, domain string) []byte {
	return NTOWFv2(password, user, domain)
}

func RC4K(key, src []byte) []byte {
	result := make([]byte, len(src))
	rc4obj, _ := rc4.NewCipher(key)
	rc4obj.XORKeyStream(result, src)
	return result
}
