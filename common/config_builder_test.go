package common

import (
	"reflect"
	"testing"
)

func TestParsePasswordsKeepsPrimaryPasswordLiteral(t *testing.T) {
	fv := &FlagVars{
		Password:     "root admin",
		AddPasswords: "pass1 pass2,pass3\tpass4",
	}

	got, err := parsePasswords(fv)
	if err != nil {
		t.Fatalf("parsePasswords error = %v", err)
	}
	want := []string{"root admin", "pass1", "pass2", "pass3", "pass4"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsePasswords() = %#v, want %#v", got, want)
	}
}

func TestBuildConfigReturnsUserFileError(t *testing.T) {
	_, _, err := BuildConfig(&FlagVars{UsersFile: "missing-users-file.txt"}, &HostInfo{})
	if err == nil {
		t.Fatal("BuildConfig should fail for missing users file")
	}
}

func TestBuildConfigReturnsPasswordFileError(t *testing.T) {
	_, _, err := BuildConfig(&FlagVars{PasswordsFile: "missing-passwords-file.txt"}, &HostInfo{})
	if err == nil {
		t.Fatal("BuildConfig should fail for missing passwords file")
	}
}

func TestBuildConfigReturnsURLFileError(t *testing.T) {
	_, _, err := BuildConfig(&FlagVars{URLsFile: "missing-urls-file.txt"}, &HostInfo{})
	if err == nil {
		t.Fatal("BuildConfig should fail for missing urls file")
	}
}

func TestBuildConfigRejectsInvalidHashValue(t *testing.T) {
	_, _, err := BuildConfig(&FlagVars{HashValue: "not-md5"}, &HostInfo{})
	if err == nil {
		t.Fatal("BuildConfig should fail for invalid hash value")
	}
}

func TestParseTargetsHostPortDoesNotLeaveSyntheticHost(t *testing.T) {
	fv := &FlagVars{Ports: "22"}
	info := &HostInfo{Host: "127.0.0.1:8080"}
	cfg := BuildConfigFromFlags(fv)
	state := NewState()

	if err := parseTargets(fv, info, cfg, state); err != nil {
		t.Fatalf("parseTargets error = %v", err)
	}

	if info.Host != "" {
		t.Fatalf("info.Host = %q, want empty after host:port extraction", info.Host)
	}
	if got := state.GetHostPorts(); !reflect.DeepEqual(got, []string{"127.0.0.1:8080"}) {
		t.Fatalf("hostPorts = %#v, want host:port target", got)
	}
}

func TestNormalizeURLKeepsUppercaseScheme(t *testing.T) {
	got := normalizeURL("HTTPS://example.com")
	if got != "HTTPS://example.com" {
		t.Fatalf("normalizeURL() = %q", got)
	}
}
