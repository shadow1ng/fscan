package common

import (
	"reflect"
	"testing"
	"time"

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

// TestModuleTimeout 测试模块超时计算
func TestModuleTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{"超时大于下限", 10 * time.Second, 10 * time.Second},
		{"超时等于下限", 3 * time.Second, 3 * time.Second},
		{"超时小于下限", 1 * time.Second, 3 * time.Second},
		{"零超时", 0, 3 * time.Second},
		{"负超时", -1 * time.Second, 3 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.Timeout = tt.timeout
			got := cfg.ModuleTimeout()
			if got != tt.want {
				t.Errorf("ModuleTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestParseUserPassPairsExactMatch 测试精确单用户单密码路径
func TestParseUserPassPairsExactMatch(t *testing.T) {
	fv := &FlagVars{
		Username: "admin",
		Password: "secret",
	}
	pairs, err := parseUserPassPairs(fv)
	if err != nil {
		t.Fatalf("parseUserPassPairs error = %v", err)
	}
	if len(pairs) != 1 {
		t.Fatalf("期望 1 个 pair, 实际 %d", len(pairs))
	}
	if pairs[0].Username != "admin" || pairs[0].Password != "secret" {
		t.Errorf("pair = %+v, want {admin secret}", pairs[0])
	}
}

// TestParseUserPassPairsMultiUserSkips 测试多用户时不生成精确 pair
func TestParseUserPassPairsMultiUserSkips(t *testing.T) {
	fv := &FlagVars{
		Username: "admin,root",
		Password: "pass",
	}
	pairs, err := parseUserPassPairs(fv)
	if err != nil {
		t.Fatalf("parseUserPassPairs error = %v", err)
	}
	if len(pairs) != 0 {
		t.Fatalf("多用户场景不应生成精确 pair, 实际 %d 个", len(pairs))
	}
}

// TestParseURLsEmpty 测试空输入返回空列表
func TestParseURLsEmpty(t *testing.T) {
	fv := &FlagVars{}
	urls, err := parseURLs(fv)
	if err != nil {
		t.Fatalf("parseURLs error = %v", err)
	}
	if len(urls) != 0 {
		t.Fatalf("空输入应返回空 url 列表, 实际 %v", urls)
	}
}

// TestParseURLsCommaSeparated 测试逗号分隔多 URL
func TestParseURLsCommaSeparated(t *testing.T) {
	fv := &FlagVars{
		TargetURL: "http://a.com,http://b.com,http://a.com", // 含重复
	}
	urls, err := parseURLs(fv)
	if err != nil {
		t.Fatalf("parseURLs error = %v", err)
	}
	if len(urls) != 2 {
		t.Fatalf("去重后应有 2 个 url, 实际 %d: %v", len(urls), urls)
	}
}

// TestParseURLsMissingFile 测试缺失文件返回错误
func TestParseURLsMissingFile(t *testing.T) {
	fv := &FlagVars{URLsFile: "nonexistent-urls.txt"}
	_, err := parseURLs(fv)
	if err == nil {
		t.Fatal("缺失文件应返回错误")
	}
}

// ---------------------------------------------------------------------------
// parseHashes
// ---------------------------------------------------------------------------

// TestParseHashesEmpty 空输入返回空结果
func TestParseHashesEmpty(t *testing.T) {
	fv := &FlagVars{}
	vals, bytes, err := parseHashes(fv)
	if err != nil {
		t.Fatalf("parseHashes error = %v", err)
	}
	if len(vals) != 0 || len(bytes) != 0 {
		t.Fatalf("空输入应返回空结果, vals=%v bytes=%v", vals, bytes)
	}
}

// TestParseHashesValidNTLM 纯 32 字符 hex hash
func TestParseHashesValidNTLM(t *testing.T) {
	hash := "aabbccddeeff00112233445566778899"
	fv := &FlagVars{HashValue: hash}
	vals, hashBytes, err := parseHashes(fv)
	if err != nil {
		t.Fatalf("parseHashes error = %v", err)
	}
	if len(vals) != 1 || vals[0] != hash {
		t.Fatalf("vals = %v, want [%s]", vals, hash)
	}
	if len(hashBytes) != 1 || len(hashBytes[0]) != 16 {
		t.Fatalf("hashBytes length wrong: %v", hashBytes)
	}
}

// TestParseHashesLMNTFormat LM:NT 格式，提取 NT 部分
func TestParseHashesLMNTFormat(t *testing.T) {
	lm := "aad3b435b51404eeaad3b435b51404ee"
	nt := "31d6cfe0d16ae931b73c59d7e0c089c0"
	fv := &FlagVars{HashValue: lm + ":" + nt}
	vals, _, err := parseHashes(fv)
	if err != nil {
		t.Fatalf("parseHashes error = %v", err)
	}
	if len(vals) != 1 || vals[0] != nt {
		t.Fatalf("vals = %v, want [%s]", vals, nt)
	}
}

// TestParseHashesInvalidLength hash 长度不是 32 → error
func TestParseHashesInvalidLength(t *testing.T) {
	fv := &FlagVars{HashValue: "tooshort"}
	_, _, err := parseHashes(fv)
	if err == nil {
		t.Fatal("hash 长度不足应返回错误")
	}
}

// TestParseHashesInvalidHex 32 字符但含非 hex 字符 → error
func TestParseHashesInvalidHex(t *testing.T) {
	fv := &FlagVars{HashValue: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}
	_, _, err := parseHashes(fv)
	if err == nil {
		t.Fatal("非 hex 字符应返回错误")
	}
}

// TestParseHashesMissingFile hash 文件不存在 → error
func TestParseHashesMissingFile(t *testing.T) {
	fv := &FlagVars{HashFile: "nonexistent-hashes.txt"}
	_, _, err := parseHashes(fv)
	if err == nil {
		t.Fatal("缺失 hash 文件应返回错误")
	}
}

// ---------------------------------------------------------------------------
// parseUsernames
// ---------------------------------------------------------------------------

// TestParseUsernamesEmpty 空输入返回空结果
func TestParseUsernamesEmpty(t *testing.T) {
	fv := &FlagVars{}
	got, err := parseUsernames(fv)
	if err != nil {
		t.Fatalf("parseUsernames error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("空输入应返回空, got %v", got)
	}
}

// TestParseUsernamesCommaSeparated 逗号分隔多用户
func TestParseUsernamesCommaSeparated(t *testing.T) {
	fv := &FlagVars{Username: "admin, root, admin"} // 含重复和空格
	got, err := parseUsernames(fv)
	if err != nil {
		t.Fatalf("parseUsernames error = %v", err)
	}
	want := []string{"admin", "root"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// TestParseUsernamesAddUsers AddUsers 追加去重
func TestParseUsernamesAddUsers(t *testing.T) {
	fv := &FlagVars{
		Username: "admin",
		AddUsers: "root,admin", // admin 重复
	}
	got, err := parseUsernames(fv)
	if err != nil {
		t.Fatalf("parseUsernames error = %v", err)
	}
	want := []string{"admin", "root"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// TestParseUsernamesMissingFile 缺失用户文件 → error
func TestParseUsernamesMissingFile(t *testing.T) {
	fv := &FlagVars{UsersFile: "nonexistent-users.txt"}
	_, err := parseUsernames(fv)
	if err == nil {
		t.Fatal("缺失用户文件应返回错误")
	}
}

// ---------------------------------------------------------------------------
// cloneStringSlice
// ---------------------------------------------------------------------------

// TestCloneStringSliceNil nil 输入返回 nil
func TestCloneStringSliceNil(t *testing.T) {
	got := cloneStringSlice(nil)
	if got != nil {
		t.Fatalf("nil 输入应返回 nil, got %v", got)
	}
}

// TestCloneStringSliceEmpty 空切片：append 无元素结果为 nil，len 为 0
func TestCloneStringSliceEmpty(t *testing.T) {
	got := cloneStringSlice([]string{})
	if len(got) != 0 {
		t.Fatalf("got len %d, want 0", len(got))
	}
}

// TestCloneStringSliceCopiesValues 正常切片：值正确且独立
func TestCloneStringSliceCopiesValues(t *testing.T) {
	src := []string{"a", "b", "c"}
	got := cloneStringSlice(src)
	if !reflect.DeepEqual(got, src) {
		t.Fatalf("got %v, want %v", got, src)
	}
	// 修改 clone 不影响原始
	got[0] = "mutated"
	if src[0] != "a" {
		t.Fatal("cloneStringSlice 返回的切片与源共享底层数组")
	}
}
