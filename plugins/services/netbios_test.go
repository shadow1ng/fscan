//go:build plugin_netbios || !plugin_selective

package services

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestParseNTLMInfoUsesFullTargetInfoOffset(t *testing.T) {
	p := NewNetBIOSPlugin()
	info := &NetBIOSInfo{}

	targetInfo := appendNTLMAVPair(nil, 0x0003, "HOST.example.local")
	targetInfo = append(targetInfo, 0x00, 0x00, 0x00, 0x00)

	const targetOffset = 300
	data := make([]byte, targetOffset+len(targetInfo))
	copy(data, "NTLMSSP\x00")
	binary.LittleEndian.PutUint16(data[40:42], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint32(data[44:48], targetOffset)
	copy(data[targetOffset:], targetInfo)

	p.parseNTLMInfo(data, info)
	if info.ComputerName != "HOST.example.local" {
		t.Fatalf("ComputerName = %q, want HOST.example.local", info.ComputerName)
	}
}

func appendNTLMAVPair(dst []byte, id uint16, value string) []byte {
	encoded := utf16.Encode([]rune(value))
	buf := make([]byte, 4+len(encoded)*2)
	binary.LittleEndian.PutUint16(buf[0:2], id)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(len(encoded)*2))
	for i, r := range encoded {
		binary.LittleEndian.PutUint16(buf[4+i*2:6+i*2], r)
	}
	return append(dst, buf...)
}
