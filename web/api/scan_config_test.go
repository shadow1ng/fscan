//go:build web

package api

import (
	"reflect"
	"testing"

	scanplugins "github.com/shadow1ng/fscan/plugins"
)

func TestBuildScanSessionUsesRequestedCredentials(t *testing.T) {
	for _, tc := range []struct {
		name     string
		username string
		password string
		want     []scanplugins.Credential
	}{
		{"single pair", "operator", " secret ", []scanplugins.Credential{{Username: "operator", Password: " secret "}}},
		{"multiple users", "alice,bob", "secret", []scanplugins.Credential{{Username: "alice", Password: "secret"}, {Username: "bob", Password: "secret"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, session, err := buildScanSession(ScanRequest{Host: "127.0.0.1", Username: tc.username, Password: tc.password})
			if err != nil {
				t.Fatal(err)
			}
			if got := scanplugins.GenerateCredentials("ssh", session.Config); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("credentials = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBuildScanSessionParsesExplicitHostPort(t *testing.T) {
	for _, host := range []string{"127.0.0.1:10001", "[::1]:10001"} {
		t.Run(host, func(t *testing.T) {
			info, session, err := buildScanSession(ScanRequest{Host: host})
			if err != nil {
				t.Fatal(err)
			}
			if got := session.State.GetHostPorts(); info.Host != "" || !reflect.DeepEqual(got, []string{host}) {
				t.Fatalf("explicit target was not parsed: host=%q, cached=%v", info.Host, got)
			}
		})
	}
}
