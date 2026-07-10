package lib

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shadow1ng/fscan/common"
)

func TestSpringActuatorSensitiveEndpointPoc(t *testing.T) {
	poc, err := LoadPocbyPath(filepath.Join("..", "pocs", "springboot-actuator-sensitive-endpoint-unauth.yml"))
	if err != nil {
		t.Fatalf("LoadPocbyPath: %v", err)
	}
	const discoveryBody = `{"_links":{"self":{"href":"http://example/actuator"},"beans":{"href":"http://example/actuator/beans"}}}`
	if got := doSearch(poc.Rules[0].Search, discoveryBody)["endpoint"]; got != "beans" {
		t.Fatalf("discovery search %q captured endpoint %q, want beans", poc.Rules[0].Search, got)
	}

	tests := []struct {
		name         string
		rootStatus   int
		verifyStatus int
		wantHit      bool
		wantRequests string
	}{
		{name: "sensitive endpoint exposed", rootStatus: http.StatusOK, verifyStatus: http.StatusOK, wantHit: true, wantRequests: "GET /actuator,HEAD /actuator/beans"},
		{name: "sensitive endpoint protected", rootStatus: http.StatusOK, verifyStatus: http.StatusUnauthorized, wantHit: false, wantRequests: "GET /actuator,HEAD /actuator/beans"},
		{name: "not actuator", rootStatus: http.StatusNotFound, verifyStatus: http.StatusNotFound, wantHit: false, wantRequests: "GET /actuator"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requestMu sync.Mutex
			requests := make([]string, 0, 2)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestMu.Lock()
				requests = append(requests, r.Method+" "+r.URL.Path)
				requestMu.Unlock()

				switch r.URL.Path {
				case "/actuator":
					w.Header().Set("Content-Type", "application/vnd.spring-boot.actuator.v3+json")
					w.WriteHeader(tt.rootStatus)
					if r.Method != http.MethodHead {
						_, _ = w.Write([]byte(discoveryBody))
					}
				case "/actuator/beans":
					w.Header().Set("Content-Type", "application/vnd.spring-boot.actuator.v3+json")
					w.WriteHeader(tt.verifyStatus)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			cfg := common.NewConfig()
			cfg.Output.Silent = true
			cfg.Network.WebTimeout = 5 * time.Second
			cfg.Network.MaxRedirects = 1
			session := common.NewScanSession(cfg, common.NewState(), &common.FlagVars{})
			if err := InitSessionHTTP(cfg, session); err != nil {
				t.Fatalf("InitSessionHTTP: %v", err)
			}
			defer session.Deactivate()

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatalf("NewRequestWithContext: %v", err)
			}
			hit, _, err := executePoc(req, poc, &POCContext{Session: session})
			if err != nil {
				t.Fatalf("executePoc: %v", err)
			}
			if hit != tt.wantHit {
				t.Fatalf("executePoc hit = %v, want %v", hit, tt.wantHit)
			}

			requestMu.Lock()
			gotRequests := strings.Join(requests, ",")
			requestMu.Unlock()
			if gotRequests != tt.wantRequests {
				t.Fatalf("requests = %q, want %q", gotRequests, tt.wantRequests)
			}
		})
	}
}
