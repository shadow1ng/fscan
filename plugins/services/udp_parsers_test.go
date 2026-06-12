//go:build !plugin_selective || (plugin_dns && plugin_tftp && plugin_bacnet && plugin_snmp)

package services

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/shadow1ng/fscan/common"
)

func TestDNSRootNSQueryAndResponse(t *testing.T) {
	const id uint16 = 0x1234

	query := buildDNSRootNSQuery(id)
	if len(query) != 17 {
		t.Fatalf("query length = %d, want 17", len(query))
	}
	if got := binary.BigEndian.Uint16(query[0:2]); got != id {
		t.Fatalf("query id = %#x, want %#x", got, id)
	}
	if got := binary.BigEndian.Uint16(query[13:15]); got != 2 {
		t.Fatalf("query type = %d, want NS(2)", got)
	}

	response := make([]byte, 12)
	binary.BigEndian.PutUint16(response[0:2], id)
	binary.BigEndian.PutUint16(response[2:4], 0x8183)
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], 2)
	binary.BigEndian.PutUint16(response[8:10], 3)
	binary.BigEndian.PutUint16(response[10:12], 4)

	banner, ok := parseDNSResponse(response, id)
	if !ok {
		t.Fatal("expected DNS response to parse")
	}
	for _, want := range []string{"rcode=3", "qd=1", "an=2", "ns=3", "ar=4"} {
		if !strings.Contains(banner, want) {
			t.Fatalf("banner %q missing %q", banner, want)
		}
	}

	if _, ok := parseDNSResponse(response, id+1); ok {
		t.Fatal("response with wrong id should not parse")
	}
	response[2] = 0
	if _, ok := parseDNSResponse(response, id); ok {
		t.Fatal("query packet should not parse as response")
	}
}

func TestTFTPRequestAndResponseParsing(t *testing.T) {
	req := buildTFTPReadRequest("probe")
	want := []byte{0, 1, 'p', 'r', 'o', 'b', 'e', 0, 'o', 'c', 't', 'e', 't', 0}
	if string(req) != string(want) {
		t.Fatalf("request = %v, want %v", req, want)
	}

	if banner, ok := parseTFTPResponse([]byte{0, 3, 0, 1}); !ok || banner != "TFTP DATA response" {
		t.Fatalf("DATA parse = %q/%v", banner, ok)
	}
	if banner, ok := parseTFTPResponse([]byte{0, 5, 0, 1, 'n', 'o', 't', ' ', 'f', 'o', 'u', 'n', 'd', 0}); !ok || banner != "TFTP not found" {
		t.Fatalf("ERROR parse = %q/%v", banner, ok)
	}
	if banner, ok := parseTFTPResponse([]byte{0, 5, 0, 1, 0}); !ok || banner != "TFTP error response" {
		t.Fatalf("empty ERROR parse = %q/%v", banner, ok)
	}
	if _, ok := parseTFTPResponse([]byte{0, 9, 0, 1}); ok {
		t.Fatal("unknown opcode should not parse")
	}
}

func TestBACnetResponseParsing(t *testing.T) {
	data := []byte{0x81, 0x0a, 0x00, 0x08, 0x01, 0x20, 0x10, 0x00}
	if banner, ok := parseBACnetResponse(data); !ok || banner != "BACnet I-Am response" {
		t.Fatalf("BACnet parse = %q/%v", banner, ok)
	}
	if _, ok := parseBACnetResponse([]byte{0x81, 0x0a, 0x00, 0x09, 0x01, 0x20, 0x10, 0x00}); ok {
		t.Fatal("bad BACnet length should not parse")
	}
	if _, ok := parseBACnetResponse([]byte{0x82, 0x0a, 0x00, 0x06, 0x10, 0x00}); ok {
		t.Fatal("bad BACnet marker should not parse")
	}
}

func TestSNMPBuildersAndCommunityList(t *testing.T) {
	req := buildSNMPGetRequest("public", []int{1, 3, 6, 1, 2, 1, 1, 1, 0})
	if len(req) == 0 || req[0] != 0x30 {
		t.Fatalf("SNMP request should be an ASN.1 sequence, got %v", req)
	}
	if got := parseSNMPResponse(nil); got != "" {
		t.Fatalf("nil SNMP response = %q, want empty", got)
	}

	cfg := common.NewConfig()
	cfg.Credentials.Passwords = []string{"private", "custom", "public"}
	communities := NewSNMPPlugin().buildCommunityList(cfg)
	if !containsString(communities, "public") || !containsString(communities, "private") || !containsString(communities, "custom") {
		t.Fatalf("community list missing expected entries: %v", communities)
	}
	if countString(communities, "public") != 1 || countString(communities, "private") != 1 {
		t.Fatalf("community list should deduplicate entries: %v", communities)
	}
}

func containsString(values []string, target string) bool {
	return countString(values, target) > 0
}

func countString(values []string, target string) int {
	count := 0
	for _, value := range values {
		if value == target {
			count++
		}
	}
	return count
}
