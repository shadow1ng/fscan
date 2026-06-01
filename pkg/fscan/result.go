package fscan

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// IsHost reports whether the result describes a live host.
func (r Result) IsHost() bool { return r.Type == ResultTypeHost }

// IsPort reports whether the result describes an open port.
func (r Result) IsPort() bool { return r.Type == ResultTypePort }

// IsService reports whether the result describes a service.
func (r Result) IsService() bool { return r.Type == ResultTypeService }

// IsVuln reports whether the result describes a vulnerability or credential.
func (r Result) IsVuln() bool { return r.Type == ResultTypeVuln }

// IsCredential reports whether the result describes a weak credential finding.
func (r Result) IsCredential() bool {
	if resultType, ok := r.DetailString("type"); ok && resultType == "weak_credential" {
		return true
	}
	return strings.HasPrefix(r.Status, "weak_credential:")
}

// SummarizeResults counts common result categories.
func SummarizeResults(results []Result) ResultSummary {
	var summary ResultSummary
	for _, result := range results {
		summary.Add(result)
	}
	return summary
}

// Add includes one result in the summary.
func (s *ResultSummary) Add(result Result) {
	s.Total++
	switch {
	case result.IsHost():
		s.Hosts++
	case result.IsPort():
		s.Ports++
	case result.IsService():
		s.Services++
	case result.IsVuln():
		s.Vulns++
	}
	if result.IsWeb() {
		s.Web++
	}
	if result.IsCredential() {
		s.Credentials++
	}
}

// DetailString returns a string detail value.
func (r Result) DetailString(key string) (string, bool) {
	value, ok := r.Details[key]
	if !ok || value == nil {
		return "", false
	}
	switch v := value.(type) {
	case string:
		return v, true
	case fmt.Stringer:
		return v.String(), true
	default:
		return fmt.Sprint(v), true
	}
}

// DetailInt returns an integer detail value.
func (r Result) DetailInt(key string) (int, bool) {
	value, ok := r.Details[key]
	if !ok || value == nil {
		return 0, false
	}
	switch v := value.(type) {
	case int:
		return v, true
	case int8:
		return int(v), true
	case int16:
		return int(v), true
	case int32:
		return int(v), true
	case int64:
		return intFromInt64(v)
	case uint:
		return intFromUint64(uint64(v))
	case uint8:
		return int(v), true
	case uint16:
		return int(v), true
	case uint32:
		return intFromUint64(uint64(v))
	case uint64:
		return intFromUint64(v)
	case float32:
		return intFromFloat64(float64(v))
	case float64:
		return intFromFloat64(v)
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		return n, err == nil
	case fmt.Stringer:
		n, err := strconv.Atoi(strings.TrimSpace(v.String()))
		return n, err == nil
	default:
		return 0, false
	}
}

// DetailBool returns a boolean detail value.
func (r Result) DetailBool(key string) (bool, bool) {
	value, ok := r.Details[key]
	if !ok || value == nil {
		return false, false
	}
	switch v := value.(type) {
	case bool:
		return v, true
	case string:
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		return b, err == nil
	default:
		return false, false
	}
}

// Port returns the result port from details, or from a target in host:port form.
func (r Result) Port() (int, bool) {
	if port, ok := r.DetailInt("port"); ok {
		return port, true
	}
	if _, portText, err := net.SplitHostPort(r.Target); err == nil {
		port, err := strconv.Atoi(portText)
		return port, err == nil
	}
	if strings.Count(r.Target, ":") == 1 {
		if idx := strings.LastIndex(r.Target, ":"); idx >= 0 && idx+1 < len(r.Target) {
			port, err := strconv.Atoi(r.Target[idx+1:])
			return port, err == nil
		}
	}
	return 0, false
}

// Service returns the detected service name when present.
func (r Result) Service() (string, bool) { return r.DetailString("service") }

// Plugin returns the plugin that produced the result when present.
func (r Result) Plugin() (string, bool) { return r.DetailString("plugin") }

// Username returns the credential username when present.
func (r Result) Username() (string, bool) { return r.DetailString("username") }

// Password returns the credential password when present.
func (r Result) Password() (string, bool) { return r.DetailString("password") }

// Banner returns the service banner when present.
func (r Result) Banner() (string, bool) { return r.DetailString("banner") }

// Vulnerability returns the vulnerability description when present.
func (r Result) Vulnerability() (string, bool) { return r.DetailString("vulnerability") }

// URL returns the web result URL when present.
func (r Result) URL() (string, bool) { return r.DetailString("url") }

// Protocol returns the detected protocol when present.
func (r Result) Protocol() (string, bool) { return r.DetailString("protocol") }

// IsWeb reports whether the result is associated with an HTTP(S) service.
func (r Result) IsWeb() bool {
	if ok, found := r.DetailBool("is_web"); found {
		return ok
	}
	for _, getter := range []func() (string, bool){r.Service, r.Protocol} {
		value, ok := getter()
		if !ok {
			continue
		}
		value = strings.ToLower(value)
		if value == "http" || value == "https" {
			return true
		}
	}
	return false
}

// AsPort returns a typed port result when the result describes an open port.
func (r Result) AsPort() (PortResult, bool) {
	if !r.IsPort() {
		return PortResult{}, false
	}
	port, ok := r.Port()
	if !ok {
		return PortResult{}, false
	}
	return PortResult{Target: r.Target, Port: port}, true
}

// AsService returns a typed service result when service-like fields are present.
func (r Result) AsService() (ServiceResult, bool) {
	if !r.IsService() {
		return ServiceResult{}, false
	}
	service := ServiceResult{
		Target: r.Target,
		IsWeb:  r.IsWeb(),
	}
	if port, ok := r.Port(); ok {
		service.Port = port
	}
	service.Service, _ = r.Service()
	service.Banner, _ = r.Banner()
	service.Product, _ = r.DetailString("product")
	service.Version, _ = r.DetailString("version")
	service.Protocol, _ = r.Protocol()
	service.URL, _ = r.URL()
	return service, service.Service != "" || service.Banner != "" || service.URL != "" || service.Port != 0
}

// AsCredential returns a typed credential result when the result is a weak credential.
func (r Result) AsCredential() (CredentialResult, bool) {
	if !r.IsCredential() {
		return CredentialResult{}, false
	}
	username, userOK := r.Username()
	password, passOK := r.Password()
	if !userOK && !passOK {
		return CredentialResult{}, false
	}
	service, _ := r.Service()
	return CredentialResult{
		Target:   r.Target,
		Service:  service,
		Username: username,
		Password: password,
	}, true
}

// AsVulnerability returns a typed vulnerability result when vulnerability data is present.
func (r Result) AsVulnerability() (VulnerabilityResult, bool) {
	if !r.IsVuln() || r.IsCredential() {
		return VulnerabilityResult{}, false
	}
	vulnerability, ok := r.Vulnerability()
	if !ok || vulnerability == "" {
		return VulnerabilityResult{}, false
	}
	service, _ := r.Service()
	return VulnerabilityResult{
		Target:        r.Target,
		Service:       service,
		Vulnerability: vulnerability,
	}, true
}

func intFromInt64(v int64) (int, bool) {
	max := int64(^uint(0) >> 1)
	min := -max - 1
	if v < min || v > max {
		return 0, false
	}
	return int(v), true
}

func intFromUint64(v uint64) (int, bool) {
	max := uint64(^uint(0) >> 1)
	if v > max {
		return 0, false
	}
	return int(v), true
}

func intFromFloat64(v float64) (int, bool) {
	n := int64(v)
	if float64(n) != v {
		return 0, false
	}
	return intFromInt64(n)
}
