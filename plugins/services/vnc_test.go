//go:build plugin_vnc || !plugin_selective

package services

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shadow1ng/fscan/common"
)

func TestVNCDisableBruteOnlyChecksUnauthenticatedAccess(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	var connections atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			_ = conn.Close()
		}
	}()

	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}

	cfg := common.NewConfig()
	cfg.DisableBrute = true
	session := common.NewScanSession(cfg, common.NewState(), &common.FlagVars{})
	result := NewVNCPlugin().Scan(context.Background(), &common.HostInfo{Host: host, Port: port}, session)
	if result == nil || !result.Success || result.Service != "vnc" {
		t.Fatalf("Scan() = %#v, want identified VNC service", result)
	}

	time.Sleep(20 * time.Millisecond)
	if got := connections.Load(); got != 1 {
		t.Fatalf("connections = %d, want one unauthenticated-access check and no password attempts", got)
	}
}

func TestClassifyVNCErrorType(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorType
	}{
		{"nil error", nil, ErrorTypeUnknown},
		{"authentication failed", errors.New("authentication failed"), ErrorTypeAuth},
		{"too many authentication failures", errors.New("too many authentication failures"), ErrorTypeNetwork},
		{"connection refused", errors.New("connection refused"), ErrorTypeNetwork},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyVNCErrorType(tt.err)
			if got != tt.want {
				t.Errorf("classifyVNCErrorType(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
