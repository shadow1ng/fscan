//go:build plugin_mssql || !plugin_selective

package services

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

func TestMSSQLLogin7DoesNotExposeClientIdentity(t *testing.T) {
	var packet bytes.Buffer
	if err := mssqlSendLogin7(&packet, "target-host", "sa", "password"); err != nil {
		t.Fatalf("mssqlSendLogin7() error = %v", err)
	}

	data := packet.Bytes()
	if len(data) < 8+20 {
		t.Fatalf("login packet too short: %d", len(data))
	}

	payload := data[8:]
	if pid := binary.LittleEndian.Uint32(payload[16:20]); pid != 0 {
		t.Fatalf("client pid = %d, want 0", pid)
	}

	for _, value := range []string{"fscan", "target-host"} {
		if bytes.Contains(payload, mssqlUCS2(value)) {
			t.Fatalf("login packet contains client-identifying value %q", value)
		}
	}

	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		if bytes.Contains(payload, mssqlUCS2(hostname)) {
			t.Fatalf("login packet contains local hostname %q", hostname)
		}
	}
}
