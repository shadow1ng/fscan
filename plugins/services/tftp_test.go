//go:build plugin_tftp || !plugin_selective

package services

import (
	"strings"
	"testing"
)

func TestTFTPReadRequestAndResponse(t *testing.T) {
	req := buildTFTPReadRequest("probe")
	want := []byte{0x00, 0x01, 'p', 'r', 'o', 'b', 'e', 0x00, 'o', 'c', 't', 'e', 't', 0x00}
	if string(req) != string(want) {
		t.Fatalf("unexpected tftp request: %#v", req)
	}

	banner, ok := parseTFTPResponse([]byte{0x00, 0x05, 0x00, 0x01, 'n', 'o', 't', ' ', 'f', 'o', 'u', 'n', 'd', 0x00})
	if !ok || !strings.Contains(banner, "not found") {
		t.Fatalf("unexpected tftp banner: %q ok=%v", banner, ok)
	}
}
