//go:build plugin_smb || !plugin_selective

package services

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

type chunkedSMBConn struct {
	data      []byte
	chunkSize int
}

func (c *chunkedSMBConn) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := len(c.data)
	if c.chunkSize > 0 && n > c.chunkSize {
		n = c.chunkSize
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, c.data[:n])
	c.data = c.data[n:]
	return n, nil
}

func (c *chunkedSMBConn) Write([]byte) (int, error)       { return 0, nil }
func (c *chunkedSMBConn) Close() error                    { return nil }
func (c *chunkedSMBConn) LocalAddr() net.Addr             { return nil }
func (c *chunkedSMBConn) RemoteAddr() net.Addr            { return nil }
func (c *chunkedSMBConn) SetDeadline(time.Time) error     { return nil }
func (c *chunkedSMBConn) SetReadDeadline(time.Time) error { return nil }
func (c *chunkedSMBConn) SetWriteDeadline(time.Time) error {
	return nil
}

func TestReadSMBMessageHandlesChunkedReads(t *testing.T) {
	got, err := readSMBMessage(&chunkedSMBConn{data: []byte{0, 0, 0, 3, 'S', 'M', 'B'}, chunkSize: 1})
	if err != nil {
		t.Fatalf("readSMBMessage() error = %v", err)
	}
	if string(got) != "\x00\x00\x00\x03SMB" {
		t.Fatalf("readSMBMessage() = %q", got)
	}
}

// ---- parseUnicodeString ----

func TestParseUnicodeString(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"empty", []byte{}, ""},
		{"odd length", []byte{0x41}, ""},
		{"null terminated", []byte{0x41, 0x00, 0x00, 0x00}, "A"},
		{"ascii", []byte{0x41, 0x00, 0x42, 0x00, 0x43, 0x00}, "ABC"},
		{"chinese", []byte{0x2d, 0x4e, 0x87, 0x65}, "中文"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseUnicodeString(tt.data); got != tt.want {
				t.Errorf("parseUnicodeString() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---- bytesToUint16 / bytesToUint32 ----

func TestBytesToUint16(t *testing.T) {
	if got := bytesToUint16([]byte{}); got != 0 {
		t.Errorf("short data: got %d", got)
	}
	if got := bytesToUint16([]byte{0x01}); got != 0 {
		t.Errorf("single byte: got %d", got)
	}
	if got := bytesToUint16([]byte{0x34, 0x12}); got != 0x1234 {
		t.Errorf("LE decode: got 0x%04x", got)
	}
}

func TestBytesToUint32(t *testing.T) {
	if got := bytesToUint32([]byte{}); got != 0 {
		t.Errorf("empty: got %d", got)
	}
	if got := bytesToUint32([]byte{0x01, 0x02, 0x03}); got != 0 {
		t.Errorf("short: got %d", got)
	}
	if got := bytesToUint32([]byte{0x78, 0x56, 0x34, 0x12}); got != 0x12345678 {
		t.Errorf("LE decode: got 0x%08x", got)
	}
}

// ---- trimSMBString ----

func TestTrimSMBString(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello\x00", "hello"},
		{"\x00hello\x00", "hello"},
		{"  hello  ", "hello"},
		{"\x00", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := trimSMBString(tt.input); got != tt.want {
			t.Errorf("trimSMBString(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ---- parseNTLMFlags ----

func TestParseNTLMFlags(t *testing.T) {
	// 无标志
	if got := parseNTLMFlags(0); len(got) != 0 {
		t.Errorf("zero flags: want empty, got %v", got)
	}

	// 单标志 NEGOTIATE_UNICODE
	flags := parseNTLMFlags(0x00000001)
	if len(flags) != 1 || flags[0] != "NEGOTIATE_UNICODE" {
		t.Errorf("single flag: got %v", flags)
	}

	// 多标志 NEGOTIATE_OEM | NEGOTIATE_NTLM
	multi := parseNTLMFlags(0x00000002 | 0x00000200)
	if len(multi) != 2 {
		t.Errorf("multi flags: want 2, got %d: %v", len(multi), multi)
	}
}

// ---- parseOSVersion ----

func TestParseOSVersion(t *testing.T) {
	tests := []struct {
		name  string
		data  []byte
		check func(s string) bool
	}{
		{
			"Windows 10",
			[]byte{10, 0, 0x00, 0x47, 0, 0, 0, 0}, // build 18176 < 22000
			func(s string) bool { return s != "" && contains(s, "Windows 10") },
		},
		{
			"Windows 11",
			[]byte{10, 0, 0x00, 0x5B, 0, 0, 0, 0}, // build 23296 >= 22000
			func(s string) bool { return contains(s, "Windows 11") },
		},
		{
			"Windows 7",
			[]byte{6, 1, 0x00, 0x09, 0, 0, 0, 0},
			func(s string) bool { return contains(s, "Windows 7") },
		},
		{
			"Windows XP",
			[]byte{5, 1, 0x00, 0x0A, 0, 0, 0, 0},
			func(s string) bool { return contains(s, "Windows XP") },
		},
		{
			"Windows 2000",
			[]byte{5, 0, 0x00, 0x07, 0, 0, 0, 0},
			func(s string) bool { return contains(s, "Windows 2000") },
		},
		{
			"unknown",
			[]byte{4, 0, 0x00, 0x01, 0, 0, 0, 0},
			func(s string) bool { return contains(s, "Windows 4.0") },
		},
		{
			"too short",
			[]byte{10, 0},
			func(s string) bool { return s == "" },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &SMBTarget{}
			parseOSVersion(tt.data, info)
			if !tt.check(info.OSVersion) {
				t.Errorf("OSVersion = %q", info.OSVersion)
			}
		})
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}

// ---- parseTargetInfo ----

func TestParseTargetInfo(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		info := &SMBTarget{}
		parseTargetInfo([]byte{}, info)
		if info.ComputerName != "" || info.DomainName != "" {
			t.Error("expected empty fields")
		}
	})

	makeAVPair := func(avId uint16, value []byte) []byte {
		b := []byte{
			byte(avId), byte(avId >> 8),
			byte(len(value)), byte(len(value) >> 8),
		}
		b = append(b, value...)
		// terminator
		b = append(b, 0x00, 0x00, 0x00, 0x00)
		return b
	}

	encodeUTF16LE := func(s string) []byte {
		var b []byte
		for _, r := range s {
			b = append(b, byte(r), byte(uint16(r)>>8))
		}
		return b
	}

	t.Run("MsvAvNbComputerName", func(t *testing.T) {
		info := &SMBTarget{}
		parseTargetInfo(makeAVPair(0x0001, encodeUTF16LE("MYPC")), info)
		if info.ComputerName != "MYPC" {
			t.Errorf("ComputerName = %q", info.ComputerName)
		}
	})

	t.Run("MsvAvNbDomainName", func(t *testing.T) {
		info := &SMBTarget{}
		parseTargetInfo(makeAVPair(0x0002, encodeUTF16LE("DOMAIN")), info)
		if info.DomainName != "DOMAIN" {
			t.Errorf("DomainName = %q", info.DomainName)
		}
	})

	t.Run("MsvAvDnsComputerName_fallback", func(t *testing.T) {
		info := &SMBTarget{}
		parseTargetInfo(makeAVPair(0x0003, encodeUTF16LE("dns.host")), info)
		if info.ComputerName != "dns.host" {
			t.Errorf("ComputerName = %q", info.ComputerName)
		}
	})

	t.Run("terminator only", func(t *testing.T) {
		info := &SMBTarget{}
		parseTargetInfo([]byte{0x00, 0x00, 0x00, 0x00}, info)
		if info.ComputerName != "" || info.DomainName != "" {
			t.Error("expected empty fields")
		}
	})
}

// ---- parseNTLMChallenge ----

// buildNTLMChallengePacket 构建测试用 NTLM Challenge 包。
// targetName 和 targetInfo 均为 UTF-16LE 编码字节。
// flags 应包含 0x02000000 (NEGOTIATE_VERSION) 才会有 version 字段。
func buildNTLMChallengePacket(targetName []byte, flags uint32, targetInfo []byte, version []byte) []byte {
	// 固定头：signature(8) + msgType(4) + targetLen(2) + targetMaxLen(2) + targetOffset(4)
	// + flags(4) + challenge(8) + reserved(8) + targetInfoLen(2) + targetInfoMaxLen(2) + targetInfoOffset(4)
	// + version(8, optional) + payload
	headerSize := 56 // 8+4+2+2+4+4+8+8+2+2+4+8 (version always included here)
	targetOffset := uint32(headerSize)
	targetInfoOffset := targetOffset + uint32(len(targetName))

	buf := make([]byte, 0, headerSize+len(targetName)+len(targetInfo))

	// signature
	buf = append(buf, []byte("NTLMSSP\x00")...)
	// messageType = 2
	buf = append(buf, 0x02, 0x00, 0x00, 0x00)
	// targetLength
	buf = append(buf, byte(len(targetName)), byte(len(targetName)>>8))
	// targetMaxLength
	buf = append(buf, byte(len(targetName)), byte(len(targetName)>>8))
	// targetOffset
	buf = append(buf, byte(targetOffset), byte(targetOffset>>8), byte(targetOffset>>16), byte(targetOffset>>24))
	// flags
	buf = append(buf, byte(flags), byte(flags>>8), byte(flags>>16), byte(flags>>24))
	// challenge (8 bytes)
	buf = append(buf, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08)
	// reserved (8 bytes)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	// targetInfoLength
	buf = append(buf, byte(len(targetInfo)), byte(len(targetInfo)>>8))
	// targetInfoMaxLength
	buf = append(buf, byte(len(targetInfo)), byte(len(targetInfo)>>8))
	// targetInfoOffset
	buf = append(buf, byte(targetInfoOffset), byte(targetInfoOffset>>8), byte(targetInfoOffset>>16), byte(targetInfoOffset>>24))
	// version (8 bytes)
	if len(version) == 8 {
		buf = append(buf, version...)
	} else {
		buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	}
	// payload
	buf = append(buf, targetName...)
	buf = append(buf, targetInfo...)

	return buf
}

func TestParseNTLMChallenge(t *testing.T) {
	t.Run("too short", func(t *testing.T) {
		info := &SMBTarget{}
		parseNTLMChallenge(make([]byte, 10), info)
		if info.DomainName != "" {
			t.Error("expected no domain")
		}
	})

	t.Run("bad signature", func(t *testing.T) {
		data := make([]byte, 64)
		copy(data, "BADMAGIC")
		info := &SMBTarget{}
		parseNTLMChallenge(data, info)
		if info.DomainName != "" {
			t.Error("expected no domain")
		}
	})

	t.Run("wrong message type", func(t *testing.T) {
		data := make([]byte, 64)
		copy(data, "NTLMSSP\x00")
		data[8] = 0x01 // messageType = 1, not 2
		info := &SMBTarget{}
		parseNTLMChallenge(data, info)
		if info.DomainName != "" {
			t.Error("expected no domain for wrong message type")
		}
	})

	t.Run("valid challenge with domain", func(t *testing.T) {
		encodeUTF16LE := func(s string) []byte {
			var b []byte
			for _, r := range s {
				b = append(b, byte(r), byte(uint16(r)>>8))
			}
			return b
		}
		targetName := encodeUTF16LE("WORKGROUP")
		flags := uint32(0x00000001 | 0x00000200) // UNICODE | NTLM, no VERSION flag
		data := buildNTLMChallengePacket(targetName, flags, nil, nil)
		info := &SMBTarget{}
		parseNTLMChallenge(data, info)
		if info.DomainName != "WORKGROUP" {
			t.Errorf("DomainName = %q, want WORKGROUP", info.DomainName)
		}
	})

	t.Run("valid challenge with targetInfo and version", func(t *testing.T) {
		encodeUTF16LE := func(s string) []byte {
			var b []byte
			for _, r := range s {
				b = append(b, byte(r), byte(uint16(r)>>8))
			}
			return b
		}
		targetName := encodeUTF16LE("CORP")

		// AV_PAIR: MsvAvNbComputerName = "SERVER"
		computerNameBytes := encodeUTF16LE("SERVER")
		avPair := []byte{
			0x01, 0x00,
			byte(len(computerNameBytes)), byte(len(computerNameBytes) >> 8),
		}
		avPair = append(avPair, computerNameBytes...)
		avPair = append(avPair, 0x00, 0x00, 0x00, 0x00) // terminator

		// NEGOTIATE_VERSION flag = 0x02000000
		flags := uint32(0x02000000 | 0x00000001 | 0x00000200)
		// Windows 10 build 19041
		version := []byte{10, 0, 0xA1, 0x4A, 0x00, 0x00, 0x00, 0x0F}
		data := buildNTLMChallengePacket(targetName, flags, avPair, version)

		info := &SMBTarget{}
		parseNTLMChallenge(data, info)

		if info.DomainName != "CORP" {
			t.Errorf("DomainName = %q, want CORP", info.DomainName)
		}
		if info.ComputerName != "SERVER" {
			t.Errorf("ComputerName = %q, want SERVER", info.ComputerName)
		}
		if info.OSVersion == "" {
			t.Error("OSVersion should not be empty")
		}
		if len(info.NTLMFlags) == 0 {
			t.Error("NTLMFlags should not be empty")
		}
	})
}

// ---- classifySMBError ----

func TestClassifySMBError(t *testing.T) {
	t.Run("nil error", func(t *testing.T) {
		if got := classifySMBError(nil); got != ErrorTypeUnknown {
			t.Errorf("nil: got %v", got)
		}
	})

	t.Run("auth error keyword", func(t *testing.T) {
		err := fmt.Errorf("authentication failed")
		if got := classifySMBError(err); got != ErrorTypeAuth {
			t.Errorf("auth keyword: got %v", got)
		}
	})

	t.Run("NT status code", func(t *testing.T) {
		err := fmt.Errorf("nt_status_logon_failure")
		if got := classifySMBError(err); got != ErrorTypeAuth {
			t.Errorf("NT status: got %v", got)
		}
	})

	t.Run("network error", func(t *testing.T) {
		err := fmt.Errorf("connection refused")
		if got := classifySMBError(err); got != ErrorTypeNetwork {
			t.Errorf("network: got %v", got)
		}
	})
}

// ---- SMBProtocol.String() ----

func TestSMBProtocolString(t *testing.T) {
	tests := []struct {
		p    SMBProtocol
		want string
	}{
		{SMBProtocol1, "SMBv1"},
		{SMBProtocol2, "SMBv2"},
		{SMBProtocolUnknown, "Unknown"},
		{SMBProtocol(99), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.p.String(); got != tt.want {
			t.Errorf("SMBProtocol(%d).String() = %q, want %q", tt.p, got, tt.want)
		}
	}
}

// ---- SMBTarget.Summary() ----

func TestSMBTargetSummary(t *testing.T) {
	t.Run("only protocol", func(t *testing.T) {
		info := &SMBTarget{Protocol: SMBProtocol2}
		if got := info.Summary(); got != "SMBv2" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("full fields", func(t *testing.T) {
		info := &SMBTarget{
			Protocol:     SMBProtocol1,
			OSVersion:    "Windows 10 (Build 19041)",
			ComputerName: "MYPC",
		}
		got := info.Summary()
		if !contains(got, "SMBv1") || !contains(got, "Windows 10") || !contains(got, "MYPC") {
			t.Errorf("Summary() = %q", got)
		}
	})

	t.Run("empty optional fields", func(t *testing.T) {
		info := &SMBTarget{Protocol: SMBProtocolUnknown}
		if got := info.Summary(); got != "Unknown" {
			t.Errorf("got %q", got)
		}
	})
}

// ---- buildNTLMSSPData ----

func TestBuildNTLMSSPData(t *testing.T) {
	flags := []byte{0x07, 0x82, 0x08, 0xA2}
	got := buildNTLMSSPData(flags)
	if len(got) == 0 {
		t.Fatal("buildNTLMSSPData returned empty")
	}
	// 长度固定（实际为158字节）
	const wantLen = 158
	if len(got) != wantLen {
		t.Errorf("len = %d, want %d", len(got), wantLen)
	}
	// flags 嵌入在偏移138处
	const flagsOffset = 138
	if got[flagsOffset] != flags[0] || got[flagsOffset+1] != flags[1] ||
		got[flagsOffset+2] != flags[2] || got[flagsOffset+3] != flags[3] {
		t.Errorf("flags not embedded correctly at offset %d: got %x %x %x %x",
			flagsOffset, got[flagsOffset], got[flagsOffset+1], got[flagsOffset+2], got[flagsOffset+3])
	}
}
