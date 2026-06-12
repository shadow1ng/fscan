package proxy

import (
	"net"
	"testing"
	"time"
)

func TestHTTPDialerRejectsConnectTargetWithLineBreak(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	dialer := &httpDialer{
		config: &ProxyConfig{Timeout: time.Second},
		stats:  &ProxyStats{},
	}

	err := dialer.sendConnectRequest(client, "example.com:80\r\nX-Injected: yes")
	if err == nil {
		t.Fatal("sendConnectRequest() error = nil, want invalid target error")
	}
}
