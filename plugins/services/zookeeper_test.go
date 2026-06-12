//go:build plugin_zookeeper || !plugin_selective

package services

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestParseZooKeeperResponse(t *testing.T) {
	banner, ok := parseZooKeeperResponse([]byte("imok"))
	if !ok || banner != "ZooKeeper ruok=imok" {
		t.Fatalf("unexpected zookeeper banner: %q ok=%v", banner, ok)
	}

	if _, ok := parseZooKeeperResponse([]byte("hello")); ok {
		t.Fatal("unexpected match for non-zookeeper response")
	}

	longResp := "zk_version\t" + strings.Repeat("界", 205)
	banner, ok = parseZooKeeperResponse([]byte(longResp))
	if !ok || !utf8.ValidString(banner) || len([]rune(banner)) != 203 {
		t.Fatalf("zookeeper truncation = %q ok=%v", banner, ok)
	}
}
