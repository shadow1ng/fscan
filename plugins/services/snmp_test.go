//go:build plugin_snmp || !plugin_selective

package services

import (
	"encoding/asn1"
	"testing"

	"github.com/shadow1ng/fscan/common"
)

// --- buildSNMPGetRequest ---

func TestBuildSNMPGetRequest(t *testing.T) {
	oid := []int{1, 3, 6, 1, 2, 1, 1, 1, 0}

	t.Run("returns non-empty bytes starting with ASN.1 SEQUENCE", func(t *testing.T) {
		pkt := buildSNMPGetRequest("public", oid)
		if len(pkt) == 0 {
			t.Fatal("expected non-empty packet")
		}
		if pkt[0] != 0x30 {
			t.Errorf("first byte = 0x%02x, want 0x30 (ASN.1 SEQUENCE)", pkt[0])
		}
	})

	t.Run("different communities produce different lengths", func(t *testing.T) {
		pkt1 := buildSNMPGetRequest("public", oid)
		pkt2 := buildSNMPGetRequest("longercommunitystringhere", oid)
		if len(pkt1) >= len(pkt2) {
			t.Errorf("expected longer community to produce longer packet: len(public)=%d len(long)=%d", len(pkt1), len(pkt2))
		}
	})
}

// --- marshalOIDWithNull ---

func TestMarshalOIDWithNull(t *testing.T) {
	oid := []int{1, 3, 6, 1, 2, 1, 1, 1, 0}
	result := marshalOIDWithNull(oid)

	if len(result) == 0 {
		t.Fatal("expected non-empty bytes")
	}

	// 应包含 OID tag (0x06) 和 NULL tag (0x05)
	foundOID := false
	foundNull := false
	for _, b := range result {
		if b == 0x06 {
			foundOID = true
		}
		if b == 0x05 {
			foundNull = true
		}
	}
	if !foundOID {
		t.Error("expected OID tag 0x06 in output")
	}
	if !foundNull {
		t.Error("expected NULL tag 0x05 in output")
	}
}

// --- parseSNMPResponse ---

// buildTestSNMPResponse 构造最小合法 SNMPv2c GetResponse 包含 OctetString value
func buildTestSNMPResponse(community string, value string) []byte {
	valBytes, _ := asn1.Marshal(asn1.RawValue{Class: 0, Tag: 4, Bytes: []byte(value)})
	oidBytes, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 6, 1, 2, 1, 1, 1, 0})

	var vbContent []byte
	vbContent = append(vbContent, oidBytes...)
	vbContent = append(vbContent, valBytes...)
	varbind, _ := asn1.Marshal(asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: vbContent})
	varbindList, _ := asn1.Marshal(asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: varbind})

	reqID, _ := asn1.Marshal(12345)
	errStatus, _ := asn1.Marshal(0)
	errIndex, _ := asn1.Marshal(0)

	var pduContent []byte
	pduContent = append(pduContent, reqID...)
	pduContent = append(pduContent, errStatus...)
	pduContent = append(pduContent, errIndex...)
	pduContent = append(pduContent, varbindList...)

	// GetResponse PDU: context-specific tag 2
	pdu, _ := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 2, IsCompound: true, Bytes: pduContent})

	version, _ := asn1.Marshal(1) // SNMPv2c
	comm, _ := asn1.Marshal([]byte(community))

	var msgContent []byte
	msgContent = append(msgContent, version...)
	msgContent = append(msgContent, comm...)
	msgContent = append(msgContent, pdu...)

	msg, _ := asn1.Marshal(asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: msgContent})
	return msg
}

func TestParseSNMPResponse(t *testing.T) {
	t.Run("empty data returns empty", func(t *testing.T) {
		got := parseSNMPResponse([]byte{})
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("invalid ASN.1 returns empty", func(t *testing.T) {
		got := parseSNMPResponse([]byte{0xFF, 0xFF, 0xFF})
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("valid response returns sysDescr value", func(t *testing.T) {
		want := "Linux router 5.4.0"
		pkt := buildTestSNMPResponse("public", want)
		got := parseSNMPResponse(pkt)
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

// --- buildCommunityList ---

func TestBuildCommunityList(t *testing.T) {
	p := NewSNMPPlugin()
	cfg := &common.Config{}

	list := p.buildCommunityList(cfg)

	if len(list) == 0 {
		t.Fatal("community list must not be empty")
	}

	hasPublic := false
	hasPrivate := false
	for _, c := range list {
		if c == "public" {
			hasPublic = true
		}
		if c == "private" {
			hasPrivate = true
		}
	}
	if !hasPublic {
		t.Error("community list must contain 'public'")
	}
	if !hasPrivate {
		t.Error("community list must contain 'private'")
	}
}
