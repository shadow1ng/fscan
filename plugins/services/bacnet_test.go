//go:build plugin_bacnet || !plugin_selective

package services

import "testing"

func TestParseBACnetResponse(t *testing.T) {
	banner, ok := parseBACnetResponse([]byte{0x81, 0x0a, 0x00, 0x08, 0x01, 0x20, 0x10, 0x00})
	if !ok || banner != "BACnet I-Am response" {
		t.Fatalf("unexpected bacnet banner: %q ok=%v", banner, ok)
	}

	if _, ok := parseBACnetResponse([]byte{0x81, 0x0a, 0x00, 0x05, 0x00}); ok {
		t.Fatal("unexpected match for malformed bacnet packet")
	}
}
