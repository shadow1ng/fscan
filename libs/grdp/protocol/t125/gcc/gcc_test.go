package gcc

import (
	"bytes"
	"testing"
)

func TestClientCoreDataDoesNotExposeClientName(t *testing.T) {
	data := NewClientCoreData()
	if !bytes.Equal(data.ClientName[:], make([]byte, len(data.ClientName))) {
		t.Fatalf("client name is not empty: %x", data.ClientName)
	}
}
