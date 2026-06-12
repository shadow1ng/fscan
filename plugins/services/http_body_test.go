//go:build plugin_elasticsearch || plugin_neo4j || plugin_rabbitmq || !plugin_selective

package services

import (
	"strings"
	"testing"
)

func TestReadServiceHTTPBodyIsBounded(t *testing.T) {
	body := strings.NewReader(strings.Repeat("a", maxServiceHTTPBodyBytes+1024))
	got, err := readServiceHTTPBody(body)
	if err != nil {
		t.Fatalf("readServiceHTTPBody error = %v", err)
	}
	if len(got) != maxServiceHTTPBodyBytes {
		t.Fatalf("body len = %d, want %d", len(got), maxServiceHTTPBodyBytes)
	}
}
