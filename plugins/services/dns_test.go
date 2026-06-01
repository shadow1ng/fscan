//go:build plugin_dns || !plugin_selective

package services

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestDNSQueryAndResponse(t *testing.T) {
	const id uint16 = 0x1234
	query := buildDNSRootNSQuery(id)
	if len(query) != 17 {
		t.Fatalf("unexpected dns query length: %d", len(query))
	}
	if binary.BigEndian.Uint16(query[0:2]) != id || binary.BigEndian.Uint16(query[13:15]) != 2 {
		t.Fatalf("unexpected dns query: %#v", query)
	}

	resp := make([]byte, 12)
	binary.BigEndian.PutUint16(resp[0:2], id)
	binary.BigEndian.PutUint16(resp[2:4], 0x8180)
	binary.BigEndian.PutUint16(resp[4:6], 1)
	binary.BigEndian.PutUint16(resp[6:8], 2)
	binary.BigEndian.PutUint16(resp[8:10], 3)
	binary.BigEndian.PutUint16(resp[10:12], 4)

	banner, ok := parseDNSResponse(resp, id)
	if !ok || !strings.Contains(banner, "rcode=0") || !strings.Contains(banner, "an=2") {
		t.Fatalf("unexpected dns banner: %q ok=%v", banner, ok)
	}
}
