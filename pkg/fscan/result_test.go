package fscan

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/shadow1ng/fscan/common/output"
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

func TestResultPortFromSimpleTarget(t *testing.T) {
	result := Result{Target: "10.0.0.1:3306"}

	port, ok := result.Port()
	if !ok || port != 3306 {
		t.Fatalf("Port = %d/%v, want 3306/true", port, ok)
	}
}

func TestResultPortNoPort(t *testing.T) {
	result := Result{Target: "10.0.0.1"}
	if _, ok := result.Port(); ok {
		t.Fatal("expected no port")
	}
}

func TestResultCredentialHelpers(t *testing.T) {
	result := Result{
		Type:   ResultTypeVuln,
		Target: "127.0.0.1:22",
		Details: map[string]interface{}{
			"type":     "weak_credential",
			"service":  "ssh",
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

func TestResultCredentialViaStatusPrefix(t *testing.T) {
	result := Result{
		Type:   ResultTypeVuln,
		Target: "127.0.0.1:22",
		Status: "weak_credential: root:pass",
	}
	if !result.IsCredential() {
		t.Fatal("expected credential via status prefix")
	}
}

func TestResultNotCredentialWithoutMarker(t *testing.T) {
	result := Result{
		Type:   ResultTypeVuln,
		Target: "127.0.0.1:445",
		Status: "MS17-010",
		Details: map[string]interface{}{
			"vulnerability": "MS17-010",
		},
	}
	if result.IsCredential() {
		t.Fatal("vuln without credential marker should not be credential")
	}
}

func TestTypedResultViews(t *testing.T) {
	portResult, ok := (Result{
		Type:    ResultTypePort,
		Target:  "127.0.0.1",
		Details: map[string]interface{}{"port": 22},
	}).AsPort()
	if !ok || portResult.Port != 22 || portResult.Target != "127.0.0.1" {
		t.Fatalf("AsPort = %#v/%v, want port 22", portResult, ok)
	}

	serviceResult, ok := (Result{
		Type:   ResultTypeService,
		Target: "127.0.0.1:80",
		Details: map[string]interface{}{
			"port":     80,
			"service":  "http",
			"banner":   "nginx",
			"product":  "nginx",
			"version":  "1.25",
			"is_web":   true,
			"protocol": "http",
			"url":      "http://127.0.0.1:80",
		},
	}).AsService()
	if !ok || serviceResult.Service != "http" || serviceResult.Port != 80 || !serviceResult.IsWeb {
		t.Fatalf("AsService = %#v/%v, want http web service", serviceResult, ok)
	}

	credentialResult, ok := (Result{
		Type:   ResultTypeVuln,
		Target: "127.0.0.1:22",
		Details: map[string]interface{}{
			"type":     "weak_credential",
			"service":  "ssh",
			"username": "root",
			"password": "toor",
		},
	}).AsCredential()
	if !ok || credentialResult.Username != "root" || credentialResult.Password != "toor" {
		t.Fatalf("AsCredential = %#v/%v, want root/toor", credentialResult, ok)
	}

	vulnResult, ok := (Result{
		Type:   ResultTypeVuln,
		Target: "127.0.0.1:25",
		Details: map[string]interface{}{
			"service":       "smtp",
			"vulnerability": "open relay",
		},
	}).AsVulnerability()
	if !ok || vulnResult.Service != "smtp" || vulnResult.Vulnerability != "open relay" {
		t.Fatalf("AsVulnerability = %#v/%v, want smtp/open relay", vulnResult, ok)
	}
}

func TestAsPortNonPortResult(t *testing.T) {
	_, ok := (Result{Type: ResultTypeHost, Target: "10.0.0.1"}).AsPort()
	if ok {
		t.Fatal("AsPort should return false for non-port result")
	}
}

func TestAsPortNoPortValue(t *testing.T) {
	_, ok := (Result{Type: ResultTypePort, Target: "10.0.0.1"}).AsPort()
	if ok {
		t.Fatal("AsPort should return false when no port available")
	}
}

func TestAsServiceNonServiceResult(t *testing.T) {
	_, ok := (Result{Type: ResultTypePort, Target: "10.0.0.1"}).AsService()
	if ok {
		t.Fatal("AsService should return false for non-service result")
	}
}

func TestAsServiceNoUsefulFields(t *testing.T) {
	_, ok := (Result{Type: ResultTypeService, Target: "10.0.0.1"}).AsService()
	if ok {
		t.Fatal("AsService should return false when no useful service fields")
	}
}

func TestAsCredentialNonCredential(t *testing.T) {
	_, ok := (Result{
		Type:    ResultTypeVuln,
		Target:  "10.0.0.1:445",
		Details: map[string]interface{}{"vulnerability": "MS17-010"},
	}).AsCredential()
	if ok {
		t.Fatal("AsCredential should return false for non-credential vuln")
	}
}

func TestAsCredentialNoUsernamePassword(t *testing.T) {
	_, ok := (Result{
		Type:    ResultTypeVuln,
		Target:  "10.0.0.1:22",
		Status:  "weak_credential: ???",
		Details: map[string]interface{}{},
	}).AsCredential()
	if ok {
		t.Fatal("AsCredential should return false without username/password")
	}
}

func TestAsVulnerabilityCredentialExcluded(t *testing.T) {
	_, ok := (Result{
		Type:   ResultTypeVuln,
		Target: "10.0.0.1:22",
		Details: map[string]interface{}{
			"type":          "weak_credential",
			"vulnerability": "ssh weak password",
			"username":      "root",
			"password":      "toor",
		},
	}).AsVulnerability()
	if ok {
		t.Fatal("AsVulnerability should exclude credential results")
	}
}

func TestAsVulnerabilityEmptyVulnField(t *testing.T) {
	_, ok := (Result{
		Type:    ResultTypeVuln,
		Target:  "10.0.0.1:445",
		Details: map[string]interface{}{},
	}).AsVulnerability()
	if ok {
		t.Fatal("AsVulnerability should return false without vulnerability field")
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

func TestSummarizeEmpty(t *testing.T) {
	summary := SummarizeResults(nil)
	if summary.Total != 0 {
		t.Fatalf("Total = %d, want 0", summary.Total)
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

func TestDetailIntTypes(t *testing.T) {
	tests := []struct {
		name  string
		value interface{}
		want  int
		ok    bool
	}{
		{"int", int(42), 42, true},
		{"int8", int8(8), 8, true},
		{"int16", int16(16), 16, true},
		{"int32", int32(32), 32, true},
		{"int64", int64(64), 64, true},
		{"uint", uint(10), 10, true},
		{"uint8", uint8(8), 8, true},
		{"uint16", uint16(16), 16, true},
		{"uint32", uint32(32), 32, true},
		{"uint64", uint64(64), 64, true},
		{"float32", float32(80), 80, true},
		{"float64", float64(443), 443, true},
		{"string", "8080", 8080, true},
		{"string-spaces", " 22 ", 22, true},
		{"string-invalid", "abc", 0, false},
		{"nil", nil, 0, false},
		{"bool", true, 0, false},
		{"missing", nil, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Result{Details: map[string]interface{}{"v": tt.value}}
			if tt.name == "missing" {
				r = Result{Details: map[string]interface{}{}}
			}
			got, ok := r.DetailInt("v")
			if ok != tt.ok || got != tt.want {
				t.Fatalf("DetailInt = %d/%v, want %d/%v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestDetailIntOverflow(t *testing.T) {
	if _, ok := (Result{Details: map[string]interface{}{"v": uint64(math.MaxUint64)}}).DetailInt("v"); ok {
		t.Fatal("uint64 max should overflow")
	}
	if _, ok := (Result{Details: map[string]interface{}{"v": float64(1.5)}}).DetailInt("v"); ok {
		t.Fatal("non-integer float should fail")
	}
}

type testStringer struct{ s string }

func (ts testStringer) String() string { return ts.s }

func TestDetailStringStringer(t *testing.T) {
	r := Result{Details: map[string]interface{}{"k": testStringer{"hello"}}}
	v, ok := r.DetailString("k")
	if !ok || v != "hello" {
		t.Fatalf("DetailString(Stringer) = %q/%v, want hello/true", v, ok)
	}
}

func TestDetailStringFallback(t *testing.T) {
	r := Result{Details: map[string]interface{}{"k": 42}}
	v, ok := r.DetailString("k")
	if !ok || v != "42" {
		t.Fatalf("DetailString(int) = %q/%v, want 42/true", v, ok)
	}
}

func TestDetailStringNil(t *testing.T) {
	r := Result{Details: map[string]interface{}{"k": nil}}
	_, ok := r.DetailString("k")
	if ok {
		t.Fatal("DetailString(nil) should return false")
	}
}

func TestDetailStringMissing(t *testing.T) {
	r := Result{Details: map[string]interface{}{}}
	_, ok := r.DetailString("missing")
	if ok {
		t.Fatal("DetailString(missing) should return false")
	}
}

func TestDetailIntStringer(t *testing.T) {
	r := Result{Details: map[string]interface{}{"v": testStringer{"99"}}}
	got, ok := r.DetailInt("v")
	if !ok || got != 99 {
		t.Fatalf("DetailInt(Stringer) = %d/%v, want 99/true", got, ok)
	}
}

func TestDetailBool(t *testing.T) {
	tests := []struct {
		name string
		val  interface{}
		want bool
		ok   bool
	}{
		{"true", true, true, true},
		{"false", false, false, true},
		{"string-true", "true", true, true},
		{"string-false", "false", false, true},
		{"string-1", "1", true, true},
		{"string-0", "0", false, true},
		{"string-invalid", "maybe", false, false},
		{"nil", nil, false, false},
		{"int", 1, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Result{Details: map[string]interface{}{"b": tt.val}}
			got, ok := r.DetailBool("b")
			if ok != tt.ok || got != tt.want {
				t.Fatalf("DetailBool = %v/%v, want %v/%v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestDetailBoolMissing(t *testing.T) {
	r := Result{Details: map[string]interface{}{}}
	_, ok := r.DetailBool("missing")
	if ok {
		t.Fatal("DetailBool(missing) should return false")
	}
}

func TestIsWebViaProtocol(t *testing.T) {
	r := Result{Details: map[string]interface{}{"protocol": "https"}}
	if !r.IsWeb() {
		t.Fatal("expected web via protocol=https")
	}
}

func TestIsWebViaService(t *testing.T) {
	r := Result{Details: map[string]interface{}{"service": "HTTP"}}
	if !r.IsWeb() {
		t.Fatal("expected web via service=HTTP (case-insensitive)")
	}
}

func TestIsWebFalse(t *testing.T) {
	r := Result{Details: map[string]interface{}{"service": "ssh"}}
	if r.IsWeb() {
		t.Fatal("ssh should not be web")
	}
}

func TestIsWebNoDetails(t *testing.T) {
	r := Result{}
	if r.IsWeb() {
		t.Fatal("empty result should not be web")
	}
}

func TestResultTypeHelpers(t *testing.T) {
	if !(Result{Type: ResultTypeHost}).IsHost() {
		t.Fatal("IsHost")
	}
	if !(Result{Type: ResultTypePort}).IsPort() {
		t.Fatal("IsPort")
	}
	if !(Result{Type: ResultTypeService}).IsService() {
		t.Fatal("IsService")
	}
	if !(Result{Type: ResultTypeVuln}).IsVuln() {
		t.Fatal("IsVuln")
	}
	if (Result{Type: ResultTypeHost}).IsPort() {
		t.Fatal("host should not be port")
	}
}

func TestResultURLAndVulnerability(t *testing.T) {
	r := Result{Details: map[string]interface{}{
		"url":           "http://example.com",
		"vulnerability": "CVE-2021-1234",
	}}
	if u, ok := r.URL(); !ok || u != "http://example.com" {
		t.Fatalf("URL = %q/%v", u, ok)
	}
	if v, ok := r.Vulnerability(); !ok || v != "CVE-2021-1234" {
		t.Fatalf("Vulnerability = %q/%v", v, ok)
	}
}

func TestResultProtocol(t *testing.T) {
	r := Result{Details: map[string]interface{}{"protocol": "tcp"}}
	if p, ok := r.Protocol(); !ok || p != "tcp" {
		t.Fatalf("Protocol = %q/%v", p, ok)
	}
}

func TestDetailIntNilDetails(t *testing.T) {
	r := Result{}
	_, ok := r.DetailInt("port")
	if ok {
		t.Fatal("DetailInt on nil details should return false")
	}
}

func TestDetailStringNilDetails(t *testing.T) {
	r := Result{}
	_, ok := r.DetailString("service")
	if ok {
		t.Fatal("DetailString on nil details should return false")
	}
}

func TestDetailBoolNilDetails(t *testing.T) {
	r := Result{}
	_, ok := r.DetailBool("is_web")
	if ok {
		t.Fatal("DetailBool on nil details should return false")
	}
}

func TestIsWebExplicitBoolDetail(t *testing.T) {
	r := Result{Details: map[string]interface{}{"is_web": true}}
	if !r.IsWeb() {
		t.Fatal("explicit is_web=true should mark as web")
	}

	r2 := Result{Details: map[string]interface{}{"is_web": false, "service": "http"}}
	if r2.IsWeb() {
		t.Fatal("explicit is_web=false should override service heuristic")
	}
}

func TestIntFromInt64Overflow(t *testing.T) {
	if _, ok := intFromInt64(math.MaxInt64); !ok {
		t.Fatal("max int64 should fit on 64-bit")
	}
}

func TestIntFromUint64Overflow(t *testing.T) {
	if _, ok := intFromUint64(math.MaxUint64); ok {
		t.Fatal("max uint64 should overflow int")
	}
	if v, ok := intFromUint64(0); !ok || v != 0 {
		t.Fatalf("intFromUint64(0) = %d/%v", v, ok)
	}
}

func TestIntFromFloat64NonInteger(t *testing.T) {
	if _, ok := intFromFloat64(3.14); ok {
		t.Fatal("non-integer float should fail")
	}
	if v, ok := intFromFloat64(100.0); !ok || v != 100 {
		t.Fatalf("intFromFloat64(100.0) = %d/%v", v, ok)
	}
}

func TestResultSummaryAddWebCredential(t *testing.T) {
	var s ResultSummary
	s.Add(Result{
		Type:   ResultTypeVuln,
		Target: "10.0.0.1:80",
		Status: "weak_credential: admin:admin",
		Details: map[string]interface{}{
			"service":  "http",
			"is_web":   true,
			"username": "admin",
			"password": "admin",
		},
	})
	if s.Vulns != 1 || s.Web != 1 || s.Credentials != 1 {
		t.Fatalf("summary = %+v, want vulns=1 web=1 credentials=1", s)
	}
}

func TestAsServiceWithPortOnly(t *testing.T) {
	sr, ok := (Result{
		Type:    ResultTypeService,
		Target:  "10.0.0.1:3306",
		Details: map[string]interface{}{"port": 3306},
	}).AsService()
	if !ok || sr.Port != 3306 {
		t.Fatalf("AsService with port only = %#v/%v", sr, ok)
	}
}

func TestConvertOutputResultNil(t *testing.T) {
	_, ok := convertOutputResult(nil)
	if ok {
		t.Fatal("convertOutputResult(nil) should return false")
	}
}

func TestConvertOutputResultEmpty(t *testing.T) {
	_, ok := convertOutputResult(&output.ScanResult{})
	if ok {
		t.Fatal("empty output result should return false")
	}
}

func TestConvertOutputResultValid(t *testing.T) {
	raw := &output.ScanResult{
		Type:   output.ResultType(ResultTypePort),
		Target: "10.0.0.1",
		Status: "open",
		Details: map[string]interface{}{
			"port": 22,
		},
	}
	r, ok := convertOutputResult(raw)
	if !ok {
		t.Fatal("expected valid conversion")
	}
	if r.Type != ResultTypePort || r.Target != "10.0.0.1" {
		t.Fatalf("converted = %#v", r)
	}
}

func TestResultJSON(t *testing.T) {
	r := Result{
		Type:   ResultTypePort,
		Target: "10.0.0.1",
		Status: "open",
		Details: map[string]interface{}{
			"port": 22,
		},
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Result
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Type != ResultTypePort || decoded.Target != "10.0.0.1" {
		t.Fatalf("round-trip failed: %#v", decoded)
	}
}

func TestPortResultJSON(t *testing.T) {
	pr := PortResult{Target: "10.0.0.1", Port: 80}
	data, err := json.Marshal(pr)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != `{"target":"10.0.0.1","port":80}` {
		t.Fatalf("PortResult JSON = %s", got)
	}
}

func TestServiceResultJSON(t *testing.T) {
	sr := ServiceResult{Target: "10.0.0.1:80", Port: 80, Service: "http", IsWeb: true}
	data, err := json.Marshal(sr)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ServiceResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Service != "http" || !decoded.IsWeb {
		t.Fatalf("round-trip failed: %#v", decoded)
	}
}

func TestCredentialResultJSON(t *testing.T) {
	cr := CredentialResult{Target: "10.0.0.1:22", Service: "ssh", Username: "root", Password: "toor"}
	data, err := json.Marshal(cr)
	if err != nil {
		t.Fatal(err)
	}
	var decoded CredentialResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Username != "root" || decoded.Password != "toor" {
		t.Fatalf("round-trip failed: %#v", decoded)
	}
}

func TestVulnerabilityResultJSON(t *testing.T) {
	vr := VulnerabilityResult{Target: "10.0.0.1:445", Service: "smb", Vulnerability: "MS17-010"}
	data, err := json.Marshal(vr)
	if err != nil {
		t.Fatal(err)
	}
	var decoded VulnerabilityResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Vulnerability != "MS17-010" {
		t.Fatalf("round-trip failed: %#v", decoded)
	}
}

func TestResultSummaryJSON(t *testing.T) {
	summary := ResultSummary{Total: 10, Hosts: 2, Ports: 3, Services: 3, Vulns: 2}
	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ResultSummary
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Total != 10 || decoded.Hosts != 2 {
		t.Fatalf("round-trip failed: %#v", decoded)
	}
}

