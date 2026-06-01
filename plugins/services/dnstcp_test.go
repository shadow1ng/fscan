//go:build plugin_dnstcp || !plugin_selective

package services

import (
	"encoding/binary"
	"testing"
)

func TestDNSTCPFrame(t *testing.T) {
	query := buildDNSRootNSQuery(0x4321)
	frame := make([]byte, 2, len(query)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	frame = append(frame, query...)

	if binary.BigEndian.Uint16(frame[:2]) != uint16(len(query)) {
		t.Fatalf("unexpected dns tcp length prefix: %#v", frame[:2])
	}
}
