package common

import (
	"context"
	"net/http"
	"testing"

	"github.com/shadow1ng/fscan/common/proxy"
)

func TestNetworkFacadeProxyState(t *testing.T) {
	t.Cleanup(func() { proxy.AutoConfigureProxy(proxy.DefaultProxyConfig()) })
	proxy.AutoConfigureProxy(proxy.DefaultProxyConfig())

	if IsProxyEnabled() || IsSOCKS5Proxy() || !IsProxyReliable() {
		t.Fatal("direct global proxy state should be disabled and reliable")
	}

	proxy.AutoConfigureProxy(&proxy.ProxyConfig{Type: proxy.ProxyTypeSOCKS5})
	if !IsProxyEnabled() || !IsSOCKS5Proxy() || !IsProxyReliable() {
		t.Fatal("SOCKS5 global proxy state should be enabled and SOCKS5")
	}
}

func TestSafeHTTPDoUsesGlobalPacketLimit(t *testing.T) {
	previousConfig := GetGlobalConfig()
	previousState := GetGlobalState()
	t.Cleanup(func() {
		SetGlobalConfig(previousConfig)
		SetGlobalState(previousState)
	})

	cfg := NewConfig()
	cfg.Network.MaxPacketCount = 1
	state := NewState()
	state.IncrementPacketCount()
	SetGlobalConfig(cfg)
	SetGlobalState(state)

	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("transport should not be called when packet limit is reached")
		return nil, nil
	})}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	if resp, err := SafeHTTPDo(client, req); err == nil || resp != nil {
		t.Fatalf("SafeHTTPDo = resp %#v err %v, want limit error", resp, err)
	}
}
