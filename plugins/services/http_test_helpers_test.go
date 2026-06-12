//go:build !plugin_selective || plugin_neo4j || plugin_rabbitmq

package services

import (
	"net"
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
