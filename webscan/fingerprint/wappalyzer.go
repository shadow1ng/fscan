package fingerprint

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"golang.org/x/net/html"
)

var (
	//go:embed wappalyzer_v0071_compat.json
	wappalyzerV0071CompatibilityData []byte

	wappalyzerOnce          sync.Once
	wappalyzerClient        *wappalyzer.Wappalyze
	wappalyzerCompatibility map[string]*compiledCompatibilityFingerprint
)

type rawCompatibilityDatabase struct {
	Apps map[string]rawCompatibilityFingerprint `json:"apps"`
}

type rawCompatibilityFingerprint struct {
	Headers map[string]string   `json:"headers"`
	Cookies map[string]string   `json:"cookies"`
	HTML    []string            `json:"html"`
	Meta    map[string][]string `json:"meta"`
	Implies []string            `json:"implies"`
}

type compiledCompatibilityFingerprint struct {
	headers map[string]*wappalyzer.ParsedPattern
	cookies map[string]*wappalyzer.ParsedPattern
	html    []*wappalyzer.ParsedPattern
	meta    map[string][]*wappalyzer.ParsedPattern
	implies []string
}

// MatchWappalyzerFingerprints combines the current full ProjectDiscovery
// Wappalyzer database with the runtime-effective static rules that existed in
// the v0.0.71 database embedded in the compared f binary but changed later.
// Both matchers are initialized once and are safe for concurrent read-only use.
func MatchWappalyzerFingerprints(body []byte, headers http.Header) []string {
	wappalyzerOnce.Do(initializeWappalyzer)

	matches := make(map[string]struct{})
	if wappalyzerClient != nil {
		for name := range wappalyzerClient.Fingerprint(map[string][]string(headers), body) {
			matches[name] = struct{}{}
		}
	}
	matchWappalyzerCompatibility(matches, body, headers)

	result := make([]string, 0, len(matches))
	for name := range matches {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func initializeWappalyzer() {
	client, err := wappalyzer.New()
	if err == nil {
		wappalyzerClient = client
	}
	wappalyzerCompatibility = compileCompatibilityDatabase(wappalyzerV0071CompatibilityData)
}

func compileCompatibilityDatabase(data []byte) map[string]*compiledCompatibilityFingerprint {
	var raw rawCompatibilityDatabase
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}

	compiled := make(map[string]*compiledCompatibilityFingerprint, len(raw.Apps))
	for name, source := range raw.Apps {
		fingerprint := &compiledCompatibilityFingerprint{
			headers: compileCompatibilityMap(source.Headers),
			cookies: compileCompatibilityMap(source.Cookies),
			html:    compileCompatibilityPatterns(source.HTML),
			meta:    make(map[string][]*wappalyzer.ParsedPattern, len(source.Meta)),
			implies: append([]string(nil), source.Implies...),
		}
		for key, patterns := range source.Meta {
			fingerprint.meta[strings.ToLower(key)] = compileCompatibilityPatterns(patterns)
		}
		compiled[name] = fingerprint
	}
	return compiled
}

func compileCompatibilityMap(source map[string]string) map[string]*wappalyzer.ParsedPattern {
	compiled := make(map[string]*wappalyzer.ParsedPattern, len(source))
	for key, pattern := range source {
		if parsed, err := wappalyzer.ParsePattern(pattern); err == nil {
			compiled[strings.ToLower(key)] = parsed
		}
	}
	return compiled
}

func compileCompatibilityPatterns(source []string) []*wappalyzer.ParsedPattern {
	compiled := make([]*wappalyzer.ParsedPattern, 0, len(source))
	for _, pattern := range source {
		if parsed, err := wappalyzer.ParsePattern(pattern); err == nil {
			compiled = append(compiled, parsed)
		}
	}
	return compiled
}

func matchWappalyzerCompatibility(matches map[string]struct{}, body []byte, headers http.Header) {
	if len(wappalyzerCompatibility) == 0 {
		return
	}
	normalizedBody := bytes.ToLower(body)
	normalizedHeaders := normalizeCompatibilityHeaders(headers)
	meta := extractCompatibilityMeta(normalizedBody)

	for name, fingerprint := range wappalyzerCompatibility {
		matched, version := matchCompatibilityFingerprint(fingerprint, normalizedBody, normalizedHeaders, meta)
		if !matched {
			continue
		}
		if version != "" {
			name += ":" + version
		}
		matches[name] = struct{}{}
		for _, implied := range fingerprint.implies {
			matches[implied] = struct{}{}
		}
	}
}

func matchCompatibilityFingerprint(fingerprint *compiledCompatibilityFingerprint, body []byte, headers map[string]string, meta map[string][]string) (bool, string) {
	matched := false
	version := ""
	for key, pattern := range fingerprint.headers {
		if value, ok := headers[key]; ok {
			if valid, foundVersion := pattern.Evaluate(value); valid {
				matched = true
				version = preferCompatibilityVersion(version, foundVersion)
			}
		}
	}
	for key, pattern := range fingerprint.cookies {
		if value, ok := headers["set-cookie"]; ok && strings.Contains(value, key+"=") {
			if valid, foundVersion := pattern.Evaluate(value); valid {
				matched = true
				version = preferCompatibilityVersion(version, foundVersion)
			}
		}
	}
	for _, pattern := range fingerprint.html {
		if valid, foundVersion := pattern.Evaluate(string(body)); valid {
			matched = true
			version = preferCompatibilityVersion(version, foundVersion)
		}
	}
	for key, patterns := range fingerprint.meta {
		for _, value := range meta[key] {
			for _, pattern := range patterns {
				if valid, foundVersion := pattern.Evaluate(value); valid {
					matched = true
					version = preferCompatibilityVersion(version, foundVersion)
				}
			}
		}
	}
	return matched, version
}

func normalizeCompatibilityHeaders(headers http.Header) map[string]string {
	normalized := make(map[string]string, len(headers))
	for key, values := range headers {
		normalized[strings.ToLower(key)] = strings.ToLower(strings.Join(values, ", "))
	}
	return normalized
}

func extractCompatibilityMeta(body []byte) map[string][]string {
	result := make(map[string][]string)
	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	for {
		switch tokenizer.Next() {
		case html.ErrorToken:
			return result
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			if token.Data != "meta" {
				continue
			}
			var name, content string
			for _, attribute := range token.Attr {
				switch attribute.Key {
				case "name", "property":
					if name == "" {
						name = strings.ToLower(attribute.Val)
					}
				case "content":
					content = strings.ToLower(attribute.Val)
				}
			}
			if name != "" {
				result[name] = append(result[name], content)
			}
		}
	}
}

func preferCompatibilityVersion(current, candidate string) string {
	if current == "" {
		return candidate
	}
	if candidate != "" && len(strings.Split(candidate, ".")) > len(strings.Split(current, ".")) {
		return candidate
	}
	return current
}
