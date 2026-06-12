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

func TestMSSQLReadMessageRejectsOversizedMultipartMessage(t *testing.T) {
	var packet bytes.Buffer
	remaining := maxTDSMessageSize + 1
	for remaining > 0 {
		chunkLen := remaining
		if chunkLen > 65527 {
			chunkLen = 65527
		}
		remaining -= chunkLen
		status := byte(0)
		if remaining == 0 {
			status = tdsStatusEOM
		}
		header := []byte{tdsPacketReply, status, 0, 0, 0, 0, 1, 0}
		binary.BigEndian.PutUint16(header[2:4], uint16(chunkLen+8))
		packet.Write(header)
		packet.Write(bytes.Repeat([]byte{0x41}, chunkLen))
	}

	if _, _, err := mssqlReadMessage(&packet); err == nil {
		t.Fatal("mssqlReadMessage() error = nil, want oversized message error")
	}
}
