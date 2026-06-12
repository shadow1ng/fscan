//go:build plugin_nfs || !plugin_selective

package services

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

type nfsTestConn struct {
	data      []byte
	chunkSize int
	w         bytes.Buffer
}

func (c *nfsTestConn) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := len(c.data)
	if c.chunkSize > 0 && n > c.chunkSize {
		n = c.chunkSize
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, c.data[:n])
	c.data = c.data[n:]
	return n, nil
}

func (c *nfsTestConn) Write(p []byte) (int, error) { return c.w.Write(p) }

func TestNFSRPCNullCallHandlesFragmentedReads(t *testing.T) {
	p := NewNFSPlugin()
	xid := uint32(0x12340000 + 100003)
	reply := make([]byte, 24)
	binary.BigEndian.PutUint32(reply[0:4], xid)
	binary.BigEndian.PutUint32(reply[4:8], 1)

	if err := p.rpcNullCall(&nfsTestConn{data: wrapNFSReply(reply), chunkSize: 2}, 100003, 3); err != nil {
		t.Fatalf("rpcNullCall() error = %v", err)
	}
}

func TestNFSGetExportsHandlesVerifierPadding(t *testing.T) {
	p := NewNFSPlugin()
	var reply []byte
	reply = binary.BigEndian.AppendUint32(reply, 0x12345678) // xid
	reply = binary.BigEndian.AppendUint32(reply, 1)          // reply
	reply = binary.BigEndian.AppendUint32(reply, 0)          // accepted
	reply = binary.BigEndian.AppendUint32(reply, 0)          // verifier flavor
	reply = binary.BigEndian.AppendUint32(reply, 3)          // verifier length
	reply = append(reply, 'a', 'b', 'c', 0)                  // padded verifier
	reply = binary.BigEndian.AppendUint32(reply, 0)          // accept success
	reply = binary.BigEndian.AppendUint32(reply, 1)          // export follows
	reply = binary.BigEndian.AppendUint32(reply, 2)          // path length
	reply = append(reply, '/', 'x', 0, 0)                    // padded path
	reply = binary.BigEndian.AppendUint32(reply, 0)          // no groups
	reply = binary.BigEndian.AppendUint32(reply, 0)          // no more exports

	exports, err := p.getExports(&nfsTestConn{data: wrapNFSReply(reply), chunkSize: 3})
	if err != nil {
		t.Fatalf("getExports() error = %v", err)
	}
	if len(exports) != 1 || exports[0] != "/x" {
		t.Fatalf("exports = %#v, want [/x]", exports)
	}
}

func TestNFSReadRPCFragmentRejectsInvalidSize(t *testing.T) {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, 0x80000000)
	if _, err := readRPCFragment(&nfsTestConn{data: header}, 4096); err == nil {
		t.Fatal("readRPCFragment() error = nil, want invalid zero-size fragment error")
	}
}

func TestNFSParseExportListStopsOnTruncatedGroup(t *testing.T) {
	p := NewNFSPlugin()
	var data []byte
	data = binary.BigEndian.AppendUint32(data, 1)
	data = binary.BigEndian.AppendUint32(data, 2)
	data = append(data, '/', 'x', 0, 0)
	data = binary.BigEndian.AppendUint32(data, 1)
	data = binary.BigEndian.AppendUint32(data, 100)

	exports := p.parseExportList(data)
	if len(exports) != 1 || exports[0] != "/x" {
		t.Fatalf("exports = %#v, want [/x]", exports)
	}
}

func wrapNFSReply(payload []byte) []byte {
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(out[:4], uint32(len(payload))|0x80000000)
	copy(out[4:], payload)
	return out
}
