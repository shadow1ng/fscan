//go:build plugin_zookeeper || !plugin_selective

package services

import "testing"

func TestParseZooKeeperResponse(t *testing.T) {
	banner, ok := parseZooKeeperResponse([]byte("imok"))
	if !ok || banner != "ZooKeeper ruok=imok" {
		t.Fatalf("unexpected zookeeper banner: %q ok=%v", banner, ok)
	}

	if _, ok := parseZooKeeperResponse([]byte("hello")); ok {
		t.Fatal("unexpected match for non-zookeeper response")
	}
}
