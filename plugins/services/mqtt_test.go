//go:build plugin_mqtt || !plugin_selective

package services

import (
	"strings"
	"testing"
)

func TestParseMQTTConnack(t *testing.T) {
	banner, ok := parseMQTTConnack([]byte{0x20, 0x02, 0x00, 0x05})
	if !ok || !strings.Contains(banner, "not authorized") {
		t.Fatalf("unexpected mqtt banner: %q ok=%v", banner, ok)
	}

	if _, ok := parseMQTTConnack([]byte{0x10, 0x02, 0x00, 0x00}); ok {
		t.Fatal("unexpected match for non-connack packet")
	}
}
