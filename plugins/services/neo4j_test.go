package services

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/shadow1ng/fscan/common"
)

func testSession() *common.ScanSession {
	cfg := common.NewConfig()
	return common.NewScanSession(cfg, common.NewState(), &common.FlagVars{})
}

func hostInfoFromServer(t *testing.T, server *httptest.Server) *common.HostInfo {
	t.Helper()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("Parse server URL error = %v", err)
	}
	host, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("SplitHostPort error = %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("Atoi port error = %v", err)
	}
	return &common.HostInfo{Host: host, Port: port}
}

func TestNeo4jIdentifyRejectsGenericHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("plain http service"))
	}))
	defer server.Close()

	result := NewNeo4jPlugin().identifyService(context.Background(), hostInfoFromServer(t, server), testSession())
	if result.Success {
		t.Fatalf("identifyService reported generic HTTP as Neo4j: %#v", result)
	}
}

func TestNeo4jUnauthorizedRequiresNeo4jBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	result := NewNeo4jPlugin().testUnauthorizedAccess(context.Background(), hostInfoFromServer(t, server), testSession())
	if result != nil && result.Success {
		t.Fatalf("testUnauthorizedAccess reported generic 200 as Neo4j: %#v", result)
	}
}
