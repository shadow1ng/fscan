package portfinger

import "testing"

func TestProbeParserRejectsShortInputs(t *testing.T) {
	tests := []string{
		"",
		"T",
		"TCP",
		"TCP ",
		"TCP Q",
		"TCP GetRequest q",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			var probe Probe
			if err := probe.fromString(input); err == nil {
				t.Fatalf("fromString(%q) error = nil, want malformed input error", input)
			}
		})
	}
}

func TestProbeParserAcceptsMinimalValidProbe(t *testing.T) {
	var probe Probe
	if err := probe.fromString(`TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|`); err != nil {
		t.Fatalf("fromString valid probe error = %v", err)
	}
	if probe.Name != "GetRequest" || probe.Protocol != "tcp" || probe.Data == "" {
		t.Fatalf("probe parsed incorrectly: %#v", probe)
	}
}
