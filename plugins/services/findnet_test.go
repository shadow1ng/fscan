//go:build plugin_findnet || !plugin_selective

package services

import (
	"strings"
	"testing"
)

// --- hexUnicodeToString ---

func TestHexUnicodeToString(t *testing.T) {
	p := NewFindNetPlugin()

	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "empty string",
			src:  "",
			want: "",
		},
		{
			name: "UTF-16LE TEST",
			// T=0x54 E=0x45 S=0x53 T=0x54, LE pairs: 5400 4500 5300 5400
			src:  "54004500530054",
			want: "TEST",
		},
		{
			name: "odd length gets padded to 4-multiple",
			// 奇数长度补0至4的倍数："540045005300540" → "5400450053005400" → "TEST"
			src:  "540045005300540", // 15 hex chars
			want: "TEST",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := p.hexUnicodeToString(tc.src)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// --- isValidHostname ---

func TestIsValidHostname(t *testing.T) {
	p := NewFindNetPlugin()

	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "empty", input: "", want: false},
		{name: "valid hostname", input: "test-pc", want: true},
		{name: "single char", input: "a", want: false}, // regex requires at least 2 chars (start+middle+end)
		{name: "too long", input: strings.Repeat("a", 256), want: false},
		{name: "valid alphanumeric", input: "PC01", want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := p.isValidHostname(tc.input)
			if got != tc.want {
				t.Errorf("isValidHostname(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// --- isValidNetworkAddress ---

func TestIsValidNetworkAddress(t *testing.T) {
	p := NewFindNetPlugin()

	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "IPv4", input: "192.168.1.1", want: true},
		{name: "IPv6 loopback", input: "::1", want: true},
		{name: "valid hostname fallback", input: "test-host", want: true},
		{name: "invalid", input: "not_an_ip!!!", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := p.isValidNetworkAddress(tc.input)
			if got != tc.want {
				t.Errorf("isValidNetworkAddress(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// --- cleanAndValidateAddress ---

func TestCleanAndValidateAddress(t *testing.T) {
	p := NewFindNetPlugin()

	cases := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "valid IPv4 bytes",
			data: []byte("192.168.1.100"),
			want: "192.168.1.100",
		},
		{
			name: "bytes with unprintable chars around valid IP",
			data: append([]byte{0x00, 0x01}, append([]byte("10.0.0.1"), 0x00)...),
			want: "10.0.0.1",
		},
		{
			name: "invalid data returns empty",
			data: []byte{0x00, 0x01, 0x02, 0x03},
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := p.cleanAndValidateAddress(tc.data)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// --- NetworkInfo.Summary ---

func TestNetworkInfoSummary(t *testing.T) {
	t.Run("invalid returns discovery failed text", func(t *testing.T) {
		ni := &NetworkInfo{Valid: false}
		got := ni.Summary()
		if got == "" {
			t.Error("expected non-empty text for invalid NetworkInfo")
		}
		// 内容是 i18n key，只验证非空即可
	})

	t.Run("valid with hostname and IPv4", func(t *testing.T) {
		ni := &NetworkInfo{
			Valid:     true,
			Hostname:  "PC01",
			IPv4Addrs: []string{"192.168.1.1", "10.0.0.1"},
		}
		got := ni.Summary()
		if got == "" {
			t.Error("expected non-empty summary")
		}
	})
}

// --- parseNetworkInfo ---

func TestParseNetworkInfo(t *testing.T) {
	p := NewFindNetPlugin()

	t.Run("empty data returns invalid", func(t *testing.T) {
		info := p.parseNetworkInfo([]byte{})
		if info.Valid {
			t.Error("expected Valid=false for empty data")
		}
	})

	t.Run("data without valid hostname or IP returns invalid", func(t *testing.T) {
		// 全零数据，hostname 解析出空字符串，不会 Valid
		info := p.parseNetworkInfo(make([]byte, 64))
		if info.Valid {
			t.Error("expected Valid=false for zero data")
		}
	})
}
