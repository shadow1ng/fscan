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

// --- NetBIOSInfo.Summary ---

func TestNetBIOSInfoSummary(t *testing.T) {
	p := NewNetBIOSPlugin()
	_ = p // 仅用于确认插件可实例化，Summary 是值方法

	cases := []struct {
		name string
		info NetBIOSInfo
		want string
	}{
		{
			name: "invalid returns empty",
			info: NetBIOSInfo{Valid: false},
			want: "",
		},
		{
			name: "computer + domain no dot",
			info: NetBIOSInfo{Valid: true, ComputerName: "PC01", DomainName: "CORP"},
			want: "CORP\\PC01",
		},
		{
			name: "computer with dot ignores domain prefix",
			info: NetBIOSInfo{Valid: true, ComputerName: "pc01.corp.local", DomainName: "CORP"},
			want: "pc01.corp.local",
		},
		{
			name: "no computer uses server service + domain",
			info: NetBIOSInfo{Valid: true, ServerService: "SRV01", DomainName: "CORP"},
			want: "CORP\\SRV01",
		},
		{
			name: "no computer uses workstation + netbios domain",
			info: NetBIOSInfo{Valid: true, WorkstationService: "WKS01", NetBIOSDomainName: "WORKGROUP"},
			want: "WORKGROUP\\WKS01",
		},
		{
			name: "domain controller prefix",
			info: NetBIOSInfo{Valid: true, ComputerName: "DC1", DomainName: "CORP", DomainControllers: "CORP"},
			want: "DC:CORP\\DC1",
		},
		{
			name: "os version appended",
			info: NetBIOSInfo{Valid: true, ComputerName: "PC01", DomainName: "CORP", OSVersion: "Windows 10"},
			want: "CORP\\PC01 Windows 10",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.info.Summary()
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// --- parseNetBIOSNames ---

func TestParseNetBIOSNames(t *testing.T) {
	p := &NetBIOSPlugin{}

	t.Run("data too short", func(t *testing.T) {
		_, err := p.parseNetBIOSNames(make([]byte, 40))
		if err == nil {
			t.Fatal("expected error for short data")
		}
	})

	t.Run("numNames zero", func(t *testing.T) {
		data := make([]byte, 57) // index 56 = 0
		_, err := p.parseNetBIOSNames(data)
		if err == nil {
			t.Fatal("expected error for zero numNames")
		}
	})

	t.Run("parses workstation and domain records", func(t *testing.T) {
		header := make([]byte, 57)
		header[56] = 2 // 2 records

		// Record 1: WorkstationService — flagByte=0x00, nameFlags=0x04 (unique, <128)
		rec1 := make([]byte, 18)
		copy(rec1, []byte("TESTPC         ")) // 15 bytes
		rec1[15] = 0x00                       // flagByte = WorkstationService
		rec1[16] = 0x04                       // nameFlags unique
		rec1[17] = 0x00

		// Record 2: DomainName — flagByte=0x00, nameFlags=0x84 (group, >=128)
		rec2 := make([]byte, 18)
		copy(rec2, []byte("WORKGROUP      ")) // 15 bytes
		rec2[15] = 0x00                       // flagByte = DomainName for group
		rec2[16] = 0x84                       // nameFlags group
		rec2[17] = 0x00

		data := append(header, rec1...)
		data = append(data, rec2...)

		info, err := p.parseNetBIOSNames(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !info.Valid {
			t.Fatal("expected Valid=true")
		}
		if info.WorkstationService != "TESTPC" {
			t.Errorf("WorkstationService = %q, want TESTPC", info.WorkstationService)
		}
		if info.DomainName != "WORKGROUP" {
			t.Errorf("DomainName = %q, want WORKGROUP", info.DomainName)
		}
	})
}

// --- cleanOSString ---

func TestCleanOSString(t *testing.T) {
	p := &NetBIOSPlugin{}

	cases := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "empty",
			data: []byte{},
			want: "",
		},
		{
			name: "plain ascii",
			data: []byte("Windows Server 2019"),
			want: "Windows Server 2019",
		},
		{
			name: "double null splits sections, first is returned",
			data: append([]byte("Windows 10\x00\x00"), []byte("Service Pack 1")...),
			want: "Windows 10",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := p.cleanOSString(tc.data)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// --- parseUnicodeString (NetBIOSPlugin) ---

func TestNetBIOSParseUnicodeString(t *testing.T) {
	p := &NetBIOSPlugin{}

	cases := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "empty",
			data: []byte{},
			want: "",
		},
		{
			name: "odd length returns empty",
			data: []byte{0x41},
			want: "",
		},
		{
			name: "UTF-16LE AB",
			data: []byte{0x41, 0x00, 0x42, 0x00},
			want: "AB",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := p.parseUnicodeString(tc.data)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
