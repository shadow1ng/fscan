package fingerprint

import (
	"reflect"
	"testing"
)

func TestMatchDefaultCredentialHints(t *testing.T) {
	got := MatchDefaultCredentialHints([]string{
		"Apache Tomcat/9.0.82",
		"Grafana:10.2.0",
		"Vue.js",
		"tomcat",
	})
	want := []string{"admin/admin", "manager/manager", "tomcat/tomcat"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MatchDefaultCredentialHints() = %#v, want %#v", got, want)
	}
}

func TestMatchDefaultCredentialHintsAvoidsSubstringMatches(t *testing.T) {
	if got := MatchDefaultCredentialHints([]string{"Tomcat-like honeypot", "MySQL client library"}); len(got) != 0 {
		t.Fatalf("unexpected hints for non-exact fingerprints: %#v", got)
	}
}

func TestMatchDefaultCredentialHintsMarksEmptyPassword(t *testing.T) {
	got := MatchDefaultCredentialHints([]string{"phpMyAdmin"})
	want := []string{"root/<empty>", "root/root"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("phpMyAdmin hints = %#v, want %#v", got, want)
	}
}
