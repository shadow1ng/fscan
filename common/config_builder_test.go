package common

import (
	"reflect"
	"testing"

	fscanconfig "github.com/shadow1ng/fscan/common/config"
)

func TestParsePasswordsKeepsPrimaryPasswordLiteral(t *testing.T) {
	fv := &FlagVars{
		Password:     "root admin,pass0",
		AddPasswords: "pass1 pass2,pass3\tpass4",
	}

	got, err := parsePasswords(fv)
	if err != nil {
		t.Fatalf("parsePasswords error = %v", err)
	}
	// -pwd 逗号分隔，空格保留；-pwda 逗号/空格/tab 分隔
	want := []string{"root admin", "pass0", "pass1", "pass2", "pass3", "pass4"}
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

func TestBuildConfigDefaultsAreIndependentCopies(t *testing.T) {
	cfg, _, err := BuildConfig(&FlagVars{Username: "custom-user"}, &HostInfo{})
	if err != nil {
		t.Fatalf("BuildConfig error = %v", err)
	}

	defaultSSHUsers := fscanconfig.DefaultUserDict["ssh"]
	if len(defaultSSHUsers) == 1 && defaultSSHUsers[0] == "custom-user" {
		t.Fatal("BuildConfig mutated DefaultUserDict")
	}

	cfg.Credentials.Userdict["ssh"][0] = "mutated-user"
	if fscanconfig.DefaultUserDict["ssh"][0] == "mutated-user" {
		t.Fatal("Config userdict shares backing storage with DefaultUserDict")
	}

	cfg.Credentials.Passwords[0] = "mutated-password"
	if fscanconfig.DefaultPasswords[0] == "mutated-password" {
		t.Fatal("Config passwords share backing storage with DefaultPasswords")
	}

	port := 80
	cfg.PortMap[port][0] = "mutated-probe"
	if fscanconfig.DefaultPortMap[port][0] == "mutated-probe" {
		t.Fatal("Config port map shares backing storage with DefaultPortMap")
	}

	cfg.DefaultMap[0] = "mutated-default-probe"
	if fscanconfig.DefaultProbeMap[0] == "mutated-default-probe" {
		t.Fatal("Config default map shares backing storage with DefaultProbeMap")
	}
}

func TestParseUserPassPairsKeepsAdditionalCredentialFlags(t *testing.T) {
	tests := []struct {
		name string
		fv   *FlagVars
	}{
		{
			name: "additional passwords",
			fv: &FlagVars{
				Username:     "root",
				Password:     "primary",
				AddPasswords: "extra",
			},
		},
		{
			name: "additional users",
			fv: &FlagVars{
				Username: "root",
				Password: "primary",
				AddUsers: "admin",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pairs, err := parseUserPassPairs(tt.fv)
			if err != nil {
				t.Fatalf("parseUserPassPairs error = %v", err)
			}
			if len(pairs) != 0 {
				t.Fatalf("parseUserPassPairs returned exact pairs %#v; additional credential flags would be ignored", pairs)
			}
		})
	}
}

func TestNewConfigDefaultsAreIndependentCopies(t *testing.T) {
	cfg := NewConfig()

	cfg.Credentials.Userdict["ssh"][0] = "mutated-user"
	if fscanconfig.DefaultUserDict["ssh"][0] == "mutated-user" {
		t.Fatal("NewConfig userdict shares backing storage with DefaultUserDict")
	}

	cfg.Credentials.Passwords[0] = "mutated-password"
	if fscanconfig.DefaultPasswords[0] == "mutated-password" {
		t.Fatal("NewConfig passwords share backing storage with DefaultPasswords")
	}

	port := 80
	cfg.PortMap[port][0] = "mutated-probe"
	if fscanconfig.DefaultPortMap[port][0] == "mutated-probe" {
		t.Fatal("NewConfig port map shares backing storage with DefaultPortMap")
	}

	cfg.DefaultMap[0] = "mutated-default-probe"
	if fscanconfig.DefaultProbeMap[0] == "mutated-default-probe" {
		t.Fatal("NewConfig default map shares backing storage with DefaultProbeMap")
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

func TestNormalizeURLBracketsIPv6Literals(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "bare ipv6 without scheme", in: "2001:db8::1", want: "http://[2001:db8::1]"},
		{name: "bracketed ipv6 without scheme", in: "[2001:db8::1]", want: "http://[2001:db8::1]"},
		{name: "bare ipv6 with scheme", in: "http://2001:db8::1", want: "http://[2001:db8::1]"},
		{name: "bare ipv6 path without scheme", in: "2001:db8::1/admin", want: "http://[2001:db8::1]/admin"},
		{name: "bare ipv6 query without scheme", in: "2001:db8::1?debug=1", want: "http://[2001:db8::1]?debug=1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeURL(tt.in); got != tt.want {
				t.Fatalf("normalizeURL(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
