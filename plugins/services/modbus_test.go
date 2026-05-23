//go:build plugin_modbus || !plugin_selective

package services

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestModbusDeviceIDRequestAndResponse(t *testing.T) {
	req := buildModbusDeviceIDRequest(0x1001)
	if len(req) != 11 || binary.BigEndian.Uint16(req[0:2]) != 0x1001 || req[7] != 0x2b {
		t.Fatalf("unexpected modbus request: %#v", req)
	}

	header := []byte{0x10, 0x01, 0x00, 0x00, 0x00, 0x03, 0xff}
	banner, ok := parseModbusResponse(header, []byte{0x2b, 0x0e}, 0x1001)
	if !ok || !strings.Contains(banner, "Modbus TCP") {
		t.Fatalf("unexpected modbus banner: %q ok=%v", banner, ok)
	}
}
