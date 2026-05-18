package fscan

import (
	"encoding/json"
	"testing"
)

func TestResultHelpers(t *testing.T) {
	result := Result{
		Type:   ResultTypeService,
		Target: "127.0.0.1:8080",
		Status: "identified",
		Details: map[string]interface{}{
			"port":     float64(8080),
			"service":  "http",
			"plugin":   "webtitle",
			"banner":   "nginx",
			"is_web":   "true",
			"protocol": "http",
		},
	}

	if !result.IsService() || result.IsPort() {
		t.Fatalf("unexpected type helpers for %q", result.Type)
	}
	if port, ok := result.Port(); !ok || port != 8080 {
		t.Fatalf("Port = %d/%v, want 8080/true", port, ok)
	}
	if service, ok := result.Service(); !ok || service != "http" {
		t.Fatalf("Service = %q/%v, want http/true", service, ok)
	}
	if plugin, ok := result.Plugin(); !ok || plugin != "webtitle" {
		t.Fatalf("Plugin = %q/%v, want webtitle/true", plugin, ok)
	}
	if banner, ok := result.Banner(); !ok || banner != "nginx" {
		t.Fatalf("Banner = %q/%v, want nginx/true", banner, ok)
	}
	if !result.IsWeb() {
		t.Fatal("expected web result")
	}
}

func TestResultPortFallback(t *testing.T) {
	result := Result{Target: "[::1]:22"}

	port, ok := result.Port()
	if !ok || port != 22 {
		t.Fatalf("Port = %d/%v, want 22/true", port, ok)
	}
}

func TestResultPortDoesNotParseBareIPv6(t *testing.T) {
	result := Result{Target: "2001:db8::1"}

	if port, ok := result.Port(); ok {
		t.Fatalf("Port = %d/true, want false", port)
	}
}

func TestResultCredentialHelpers(t *testing.T) {
	result := Result{
		Type: ResultTypeVuln,
		Details: map[string]interface{}{
			"type":     "weak_credential",
			"username": "root",
			"password": "toor",
		},
	}

	if !result.IsVuln() {
		t.Fatal("expected vuln result")
	}
	if !result.IsCredential() {
		t.Fatal("expected credential result")
	}
	if username, ok := result.Username(); !ok || username != "root" {
		t.Fatalf("Username = %q/%v, want root/true", username, ok)
	}
	if password, ok := result.Password(); !ok || password != "toor" {
		t.Fatalf("Password = %q/%v, want toor/true", password, ok)
	}
}

func TestSummarizeResults(t *testing.T) {
	results := []Result{
		{Type: ResultTypeHost, Target: "127.0.0.1"},
		{Type: ResultTypePort, Target: "127.0.0.1", Details: map[string]interface{}{"port": 80}},
		{Type: ResultTypeService, Target: "127.0.0.1:80", Details: map[string]interface{}{"service": "http"}},
		{Type: ResultTypeVuln, Target: "127.0.0.1:22", Status: "weak_credential: root:toor"},
	}

	summary := SummarizeResults(results)
	if summary.Total != 4 {
		t.Fatalf("Total = %d, want 4", summary.Total)
	}
	if summary.Hosts != 1 || summary.Ports != 1 || summary.Services != 1 || summary.Vulns != 1 {
		t.Fatalf("summary categories = %#v, want one each", summary)
	}
	if summary.Web != 1 {
		t.Fatalf("Web = %d, want 1", summary.Web)
	}
	if summary.Credentials != 1 {
		t.Fatalf("Credentials = %d, want 1", summary.Credentials)
	}
}

func TestResultDetailIntRejectsFraction(t *testing.T) {
	result := Result{Details: map[string]interface{}{"port": 22.5}}

	if port, ok := result.DetailInt("port"); ok {
		t.Fatalf("DetailInt = %d/true, want false", port)
	}
}

func TestResultDetailIntParsesJSONNumber(t *testing.T) {
	result := Result{Details: map[string]interface{}{"port": json.Number("443")}}

	port, ok := result.DetailInt("port")
	if !ok || port != 443 {
		t.Fatalf("DetailInt = %d/%v, want 443/true", port, ok)
	}
}
