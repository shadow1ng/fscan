//go:build plugin_dns || plugin_dnstcp || plugin_modbus || !plugin_selective

package services

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"
)

func randomUint16() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err == nil {
		return binary.BigEndian.Uint16(b[:])
	}
	return uint16(time.Now().UnixNano())
}

func buildDNSRootNSQuery(id uint16) []byte {
	query := make([]byte, 17)
	binary.BigEndian.PutUint16(query[0:2], id)
	binary.BigEndian.PutUint16(query[2:4], 0x0100)
	binary.BigEndian.PutUint16(query[4:6], 1)
	query[12] = 0x00
	binary.BigEndian.PutUint16(query[13:15], 2)
	binary.BigEndian.PutUint16(query[15:17], 1)
	return query
}

func parseDNSResponse(data []byte, id uint16) (string, bool) {
	if len(data) < 12 || binary.BigEndian.Uint16(data[0:2]) != id {
		return "", false
	}
	flags := binary.BigEndian.Uint16(data[2:4])
	if flags&0x8000 == 0 {
		return "", false
	}

	rcode := flags & 0x000f
	qd := binary.BigEndian.Uint16(data[4:6])
	an := binary.BigEndian.Uint16(data[6:8])
	ns := binary.BigEndian.Uint16(data[8:10])
	ar := binary.BigEndian.Uint16(data[10:12])
	return fmt.Sprintf("DNS response rcode=%d qd=%d an=%d ns=%d ar=%d", rcode, qd, an, ns, ar), true
}
