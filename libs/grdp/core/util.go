package core

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"unicode/utf16"
)

func Reverse(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

func Random(n int) []byte {
	const alpha = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, n)
	rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = alpha[b%byte(len(alpha))]
	}
	return bytes
}

func UTF16ToLittleEndianBytes(u []uint16) []byte {
	b := make([]byte, 2*len(u))
	for index, value := range u {
		binary.LittleEndian.PutUint16(b[index*2:], value)
	}
	return b
}

func LittleEndianBytesToUTF16(u []byte) []uint16 {
	b := make([]uint16, 0, len(u)/2)
	n := make([]byte, 2)
	for i, v := range u {
		if i%2 == 0 {
			n[0] = v
		} else {
			n[1] = v
			b = append(b, binary.LittleEndian.Uint16(n))
		}
	}
	return b
}

// s.encode('utf-16le')
func UnicodeEncode(p string) []byte {
	return UTF16ToLittleEndianBytes(utf16.Encode([]rune(p)))
}

func UnicodeDecode(p []byte) string {
	r := bytes.NewReader(p)
	n := make([]uint16, 0, 100)
	for r.Len() > 0 {
		a, _ := ReadUint16LE(r)
		n = append(n, a)
	}
	//n := LittleEndianBytesToUTF16(p)
	return string(utf16.Decode(n))
}

func BytesToUint64(b []byte) uint64 {
	return binary.LittleEndian.Uint64(b)
}
