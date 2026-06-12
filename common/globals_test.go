package common

import (
	"errors"
	"strings"
	"testing"
)

func TestHostInfoTargetUsesBracketedIPv6(t *testing.T) {
	info := &HostInfo{Host: "2001:db8::1", Port: 443}
	if got, want := info.Target(), "[2001:db8::1]:443"; got != want {
		t.Fatalf("Target() = %q, want %q", got, want)
	}
}

func TestHostInfoTargetDoesNotDoubleBracketIPv6(t *testing.T) {
	info := &HostInfo{Host: "[2001:db8::1]", Port: 443}
	if got, want := info.Target(), "[2001:db8::1]:443"; got != want {
		t.Fatalf("Target() = %q, want %q", got, want)
	}
}

func TestGlobalHelpersAndPacketLimitErrors(t *testing.T) {
	if GetVersion() == "" {
		t.Fatal("GetVersion returned empty string")
	}
	if !ContainsAny("hello fscan", "none", "scan") {
		t.Fatal("ContainsAny should find a matching substring")
	}
	if ContainsAny("hello fscan", "none", "missing") {
		t.Fatal("ContainsAny should return false when nothing matches")
	}

	maxErr := &PacketLimitError{Sentinel: ErrMaxPacketReached, Limit: 5, Current: 5}
	if !errors.Is(maxErr, ErrMaxPacketReached) || !strings.Contains(maxErr.Error(), "5") {
		t.Fatalf("max packet error = %v", maxErr)
	}

	rateErr := &PacketLimitError{Sentinel: ErrPacketRateLimited, Limit: 3, Current: 2}
	if !errors.Is(rateErr, ErrPacketRateLimited) || !strings.Contains(rateErr.Error(), "3") {
		t.Fatalf("rate limit error = %v", rateErr)
	}
}

func TestCanSendPacketUsesGlobalConfigAndState(t *testing.T) {
	previousConfig := GetGlobalConfig()
	previousState := GetGlobalState()
	t.Cleanup(func() {
		SetGlobalConfig(previousConfig)
		SetGlobalState(previousState)
	})

	cfg := NewConfig()
	cfg.Network.MaxPacketCount = 1
	state := NewState()
	state.IncrementPacketCount()
	SetGlobalConfig(cfg)
	SetGlobalState(state)

	ok, reason := CanSendPacket()
	if ok {
		t.Fatal("CanSendPacket should reject when max packet count is reached")
	}
	if reason == "" {
		t.Fatal("CanSendPacket should return a rejection reason")
	}
}
