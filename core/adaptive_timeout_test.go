package core

import (
	"testing"
	"time"
)

func TestAdaptiveTimeoutKeepsHighConcurrencyFloor(t *testing.T) {
	tests := []struct {
		name       string
		maxTimeout time.Duration
		wantFloor  time.Duration
	}{
		{name: "fraction of configured timeout", maxTimeout: 3 * time.Second, wantFloor: 600 * time.Millisecond},
		{name: "absolute floor", maxTimeout: time.Second, wantFloor: 500 * time.Millisecond},
		{name: "never exceed configured maximum", maxTimeout: 200 * time.Millisecond, wantFloor: 200 * time.Millisecond},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptive := NewAdaptiveTimeout(tt.maxTimeout)
			for i := 0; i < adaptive.warmup; i++ {
				adaptive.Record(time.Millisecond)
			}

			if got := adaptive.Timeout(); got != tt.wantFloor {
				t.Fatalf("Timeout() = %v, want floor %v", got, tt.wantFloor)
			}
		})
	}
}

func TestAdaptiveTimeoutUsesConfiguredMaximumDuringWarmup(t *testing.T) {
	const maxTimeout = 3 * time.Second
	adaptive := NewAdaptiveTimeout(maxTimeout)
	for i := 0; i < adaptive.warmup-1; i++ {
		adaptive.Record(time.Millisecond)
	}

	if got := adaptive.Timeout(); got != maxTimeout {
		t.Fatalf("Timeout() during warmup = %v, want %v", got, maxTimeout)
	}
}
