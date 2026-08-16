package fingerprint

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestWappalyzerV0071CompatibilityDatabaseIsComplete(t *testing.T) {
	var database rawCompatibilityDatabase
	if err := json.Unmarshal(wappalyzerV0071CompatibilityData, &database); err != nil {
		t.Fatalf("parse compatibility database: %v", err)
	}
	if len(database.Apps) != 30 {
		t.Fatalf("compatibility app count = %d, want 30", len(database.Apps))
	}

	rules := 0
	for _, fingerprint := range database.Apps {
		rules += len(fingerprint.Headers) + len(fingerprint.Cookies) + len(fingerprint.HTML)
		for _, patterns := range fingerprint.Meta {
			rules += len(patterns)
		}
	}
	if rules != 40 {
		t.Fatalf("compatibility rule count = %d, want 40", rules)
	}
}

func TestMatchWappalyzerFingerprintsHeadersBodyAndVersion(t *testing.T) {
	body := []byte(`<html><head><meta name="generator" content="WordPress 6.8"></head></html>`)
	headers := http.Header{
		"Server":     {"nginx/1.24.0"},
		"Set-Cookie": {"laravel_session=example; Path=/; HttpOnly"},
	}

	matches := MatchWappalyzerFingerprints(body, headers)
	for _, technology := range []string{"Nginx", "WordPress", "Laravel"} {
		if !containsTechnology(matches, technology) {
			t.Fatalf("missing %s in Wappalyzer matches: %v", technology, matches)
		}
	}
}

func TestMatchWappalyzerFingerprintsPreservesComparedBinaryCompatibility(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		headers http.Header
		want    string
	}{
		{"SMF", `<a href="credits/" title="Simple Machines Forum" target="_blank" class="new_win">SMF 2.1.4</a>`, nil, "Simple Machines Forum"},
		{"Sitefinity", `<meta name="generator" content="Sitefinity 14.4">`, nil, "Progress Sitefinity"},
		{"Zyro", `<meta content="Zyro.com website builder" name="generator">`, nil, "Zyro"},
		{"eZ Platform renamed to Ibexa", `<meta name="generator" content="eZ Platform">`, nil, "Ibexa DXP"},
		{"removed header rule", ``, http.Header{"X-Powered-By": {"afosto saas bv"}}, "Afosto"},
		{"removed HTML rule", `<html data-wf-site="example"></html>`, nil, "Webflow"},
		{"removed meta rule", `<meta name="generator" content="Divi">`, nil, "Divi"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matches := MatchWappalyzerFingerprints([]byte(test.body), test.headers)
			if !containsTechnology(matches, test.want) {
				t.Fatalf("missing %s in compatibility matches: %v", test.want, matches)
			}
		})
	}
}

func TestMatchWappalyzerFingerprintsIsDeterministic(t *testing.T) {
	headers := http.Header{"Server": {"nginx"}}
	first := MatchWappalyzerFingerprints(nil, headers)
	second := MatchWappalyzerFingerprints(nil, headers)
	if strings.Join(first, "\x00") != strings.Join(second, "\x00") {
		t.Fatalf("non-deterministic results: %v != %v", first, second)
	}
}

func BenchmarkMatchWappalyzerFingerprints(b *testing.B) {
	body := []byte(`<html><head><meta name="generator" content="WordPress 6.8"><script src="/wp-includes/js/jquery.min.js"></script></head></html>`)
	headers := http.Header{"Server": {"nginx/1.24.0"}, "Set-Cookie": {"wordpress_test_cookie=1; Path=/"}}
	MatchWappalyzerFingerprints(body, headers)
	b.ResetTimer()
	for range b.N {
		MatchWappalyzerFingerprints(body, headers)
	}
}

func containsTechnology(matches []string, technology string) bool {
	for _, match := range matches {
		base := match
		if index := strings.IndexByte(base, ':'); index >= 0 {
			base = base[:index]
		}
		if strings.EqualFold(base, technology) {
			return true
		}
	}
	return false
}
