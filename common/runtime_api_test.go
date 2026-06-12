package common

import "testing"

func TestResultCallbackLifecycle(t *testing.T) {
	ClearResultCallback()
	t.Cleanup(ClearResultCallback)

	called := false
	SetResultCallback(func(result interface{}) {
		called = true
		if result != "payload" {
			t.Fatalf("callback payload = %#v", result)
		}
	})

	NotifyResult("payload")
	if !called {
		t.Fatal("callback was not called")
	}

	called = false
	ClearResultCallback()
	NotifyResult("payload")
	if called {
		t.Fatal("callback should not be called after ClearResultCallback")
	}
}

func TestStateRuntimeTargetsAndShellFlags(t *testing.T) {
	state := NewState()

	urls := []string{"http://example.com", "https://example.org"}
	state.SetURLs(urls)
	if got := state.GetURLs(); len(got) != 2 || got[0] != urls[0] || got[1] != urls[1] {
		t.Fatalf("urls = %#v", got)
	}

	hostPorts := []string{"127.0.0.1:80", "[::1]:443"}
	state.SetHostPorts(hostPorts)
	if got := state.GetHostPorts(); len(got) != 2 || got[0] != hostPorts[0] || got[1] != hostPorts[1] {
		t.Fatalf("hostPorts = %#v", got)
	}
	state.ClearHostPorts()
	if got := state.GetHostPorts(); got != nil {
		t.Fatalf("hostPorts after clear = %#v, want nil", got)
	}

	state.SetForwardShellActive(true)
	state.SetReverseShellActive(true)
	state.SetSocks5ProxyActive(true)
	if !state.IsForwardShellActive() || !state.IsReverseShellActive() || !state.IsSocks5ProxyActive() {
		t.Fatal("shell/proxy flags should be active")
	}

	state.SetForwardShellActive(false)
	state.SetReverseShellActive(false)
	state.SetSocks5ProxyActive(false)
	if state.IsForwardShellActive() || state.IsReverseShellActive() || state.IsSocks5ProxyActive() {
		t.Fatal("shell/proxy flags should be inactive")
	}
}
