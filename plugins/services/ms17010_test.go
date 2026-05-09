//go:build plugin_ms17010 || !plugin_selective

package services

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/shadow1ng/fscan/common"
)

func TestMS17010LegacyRequestsDecodeToSMB1Packets(t *testing.T) {
	requests := map[string][]byte{
		"negotiate":          negotiateProtocolRequest,
		"sessionSetup":       sessionSetupRequest,
		"treeConnect":        treeConnectRequest,
		"transNamedPipe":     transNamedPipeRequest,
		"trans2SessionSetup": trans2SessionSetupRequest,
	}

	for name, request := range requests {
		t.Run(name, func(t *testing.T) {
			if len(request) < 36 {
				t.Fatalf("request length = %d, want at least 36", len(request))
			}
			if request[0] != 0x00 {
				t.Fatalf("NetBIOS message type = 0x%02x, want 0x00", request[0])
			}
			payloadLen := int(request[1])<<16 | int(request[2])<<8 | int(request[3])
			if payloadLen != len(request)-4 {
				t.Fatalf("NetBIOS payload length = %d, want %d", payloadLen, len(request)-4)
			}
			if !bytes.Equal(request[4:8], []byte{0xff, 0x53, 0x4d, 0x42}) {
				t.Fatalf("SMB signature = % x, want ff 53 4d 42", request[4:8])
			}
		})
	}
}

func TestMS17010CheckDetectsVulnerableStatus(t *testing.T) {
	addr, cleanup := startMS17010FakeServer(t, true, 45)
	defer cleanup()

	session := newMS17010TestSession()
	vulnerable, _, _, err := NewMS17010Plugin().checkMS17010VulnerabilityAt(context.Background(), addr, session)
	if err != nil {
		t.Fatalf("checkMS17010VulnerabilityAt returned error: %v", err)
	}
	if !vulnerable {
		t.Fatal("expected vulnerable status to be detected")
	}
}

func TestMS17010CheckAcceptsMinimalSessionSetupResponse(t *testing.T) {
	addr, cleanup := startMS17010FakeServer(t, true, 36)
	defer cleanup()

	session := newMS17010TestSession()
	vulnerable, _, _, err := NewMS17010Plugin().checkMS17010VulnerabilityAt(context.Background(), addr, session)
	if err != nil {
		t.Fatalf("checkMS17010VulnerabilityAt returned error: %v", err)
	}
	if !vulnerable {
		t.Fatal("expected vulnerable status to be detected")
	}
}

func TestMS17010CheckRejectsPatchedStatus(t *testing.T) {
	addr, cleanup := startMS17010FakeServer(t, false, 45)
	defer cleanup()

	session := newMS17010TestSession()
	vulnerable, _, _, err := NewMS17010Plugin().checkMS17010VulnerabilityAt(context.Background(), addr, session)
	if err != nil {
		t.Fatalf("checkMS17010VulnerabilityAt returned error: %v", err)
	}
	if vulnerable {
		t.Fatal("expected patched status to be treated as not vulnerable")
	}
}

func TestMS17010CheckDetectsDoublePulsar(t *testing.T) {
	addr, cleanup := startMS17010FakeServer(t, true, 45, withDoublePulsar())
	defer cleanup()

	session := newMS17010TestSession()
	vulnerable, _, hasBackdoor, err := NewMS17010Plugin().checkMS17010VulnerabilityAt(context.Background(), addr, session)
	if err != nil {
		t.Fatalf("checkMS17010VulnerabilityAt returned error: %v", err)
	}
	if !vulnerable {
		t.Fatal("expected vulnerable status to be detected")
	}
	if !hasBackdoor {
		t.Fatal("expected DOUBLEPULSAR status to be detected")
	}
}

func newMS17010TestSession() *common.ScanSession {
	cfg := common.NewConfig()
	cfg.Timeout = time.Second
	return common.NewScanSession(cfg, common.NewState(), &common.FlagVars{})
}

type ms17010FakeServerOption func(*ms17010FakeServerConfig)

type ms17010FakeServerConfig struct {
	doublePulsar bool
}

func withDoublePulsar() ms17010FakeServerOption {
	return func(cfg *ms17010FakeServerConfig) {
		cfg.doublePulsar = true
	}
}

func startMS17010FakeServer(t *testing.T, vulnerable bool, sessionSetupSize int, opts ...ms17010FakeServerOption) (string, func()) {
	t.Helper()

	var cfg ms17010FakeServerConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		responses := [][]byte{
			makeMS17010Response(36),
			makeMS17010Response(sessionSetupSize),
			makeMS17010Response(36),
			makeMS17010Response(36),
		}
		if len(responses[1]) >= 34 {
			responses[1][32] = 0x34
			responses[1][33] = 0x12
		}
		responses[2][28] = 0x78
		responses[2][29] = 0x56
		if vulnerable {
			responses[3][9] = 0x05
			responses[3][10] = 0x02
			responses[3][11] = 0x00
			responses[3][12] = 0xc0
			responses = append(responses, makeMS17010Response(36))
			if cfg.doublePulsar {
				responses[4][34] = 0x51
			}
		}

		buf := make([]byte, 4096)
		for _, response := range responses {
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			if _, err := conn.Read(buf); err != nil {
				return
			}
			if _, err := conn.Write(response); err != nil {
				return
			}
		}
	}()

	cleanup := func() {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("fake server did not exit")
		}
	}

	return ln.Addr().String(), cleanup
}

func makeMS17010Response(size int) []byte {
	resp := make([]byte, size)
	if size >= 4 {
		resp[3] = byte(size - 4)
	}
	return resp
}
