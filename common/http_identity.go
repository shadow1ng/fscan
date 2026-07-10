package common

// DefaultHTTPUserAgent is used when the operator does not provide -ua.
// Keep it stable so scans are reproducible and HTTP logs remain auditable.
const DefaultHTTPUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

// HTTPUserAgent returns the configured User-Agent or the stable default.
func HTTPUserAgent(config *Config) string {
	if config != nil && config.HTTP.UserAgent != "" {
		return config.HTTP.UserAgent
	}
	return DefaultHTTPUserAgent
}
