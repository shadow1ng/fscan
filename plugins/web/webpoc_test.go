package web

import (
	"context"
	"testing"

	"github.com/shadow1ng/fscan/common"
)

func TestMatchCDNorWAF(t *testing.T) {
	tests := []struct {
		name         string
		fingerprints []string
		want         string
	}{
		{name: "empty", fingerprints: nil, want: ""},
		{name: "no match", fingerprints: []string{"nginx", "wordpress"}, want: ""},
		{name: "case insensitive cdn", fingerprints: []string{"site behind cloudflare"}, want: "CloudFlare"},
		{name: "chinese waf", fingerprints: []string{"命中安全狗防护"}, want: "安全狗"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchCDNorWAF(tt.fingerprints); got != tt.want {
				t.Fatalf("matchCDNorWAF(%v) = %q, want %q", tt.fingerprints, got, tt.want)
			}
		})
	}
}

func TestWebPocEarlyReturnBranches(t *testing.T) {
	plugin := NewWebPocPlugin()
	if plugin == nil || plugin.Name() != "webpoc" {
		t.Fatalf("unexpected plugin: %#v", plugin)
	}

	cfg := common.NewConfig()
	session := common.NewScanSession(cfg, common.NewState(), &common.FlagVars{})
	info := &common.HostInfo{Host: "example.com", Port: 80}

	cfg.POC.Disabled = true
	disabled := plugin.Scan(context.Background(), info, session)
	if !disabled.Skipped {
		t.Fatalf("disabled scan = %#v, want skipped result", disabled)
	}

	cfg.POC.Disabled = false
	cfg.POC.Full = false
	skipped := plugin.Scan(context.Background(), info, session)
	if !skipped.Success || !skipped.Skipped {
		t.Fatalf("non-full scan = %#v, want skipped success", skipped)
	}
}
