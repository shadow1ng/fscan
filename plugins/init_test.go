package plugins

import (
	"context"
	"testing"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/config"
)

/*
init_test.go - 插件系统核心逻辑测试

测试目标：GenerateCredentials 函数
价值：这个函数生成所有服务的暴力破解凭据，逻辑错误会导致：
  - 漏掉有效凭据（少生成）
  - 浪费时间测试重复凭据（多生成）
  - {user} 占位符不生效（密码错误）

"凭据生成是暴力破解的弹药库。弹药错了，仗就打不赢。"
*/

// =============================================================================
// GenerateCredentials - 核心凭据生成逻辑
// =============================================================================

func preservePluginRegistry(t *testing.T) {
	t.Helper()

	mutex.RLock()
	snapshot := make(map[string]*PluginInfo, len(plugins))
	for name, info := range plugins {
		copied := *info
		copied.ports = append([]int(nil), info.ports...)
		copied.types = append([]string(nil), info.types...)
		snapshot[name] = &copied
	}
	mutex.RUnlock()

	t.Cleanup(func() {
		mutex.Lock()
		plugins = snapshot
		mutex.Unlock()
	})
}

type testPlugin struct {
	BasePlugin
}

func (p testPlugin) Scan(context.Context, *common.HostInfo, *common.ScanSession) *Result {
	return &Result{Type: ResultTypeService, Success: true}
}

func TestPluginRegistryMetadata(t *testing.T) {
	preservePluginRegistry(t)

	RegisterWithPorts("unit_tcp", func() Plugin {
		return testPlugin{BasePlugin: NewBasePlugin("unit_tcp")}
	}, []int{1234, 5678})
	RegisterUDPWithPorts("unit_udp", func() Plugin {
		return testPlugin{BasePlugin: NewBasePlugin("unit_udp")}
	}, []int{161})
	RegisterWithTypes("unit_local", func() Plugin {
		return testPlugin{BasePlugin: NewBasePlugin("unit_local")}
	}, nil, []string{PluginTypeLocal})
	RegisterUnsafeWithTypes("unit_unsafe_web", func() Plugin {
		return testPlugin{BasePlugin: NewBasePlugin("unit_unsafe_web")}
	}, nil, []string{PluginTypeWeb})

	if !Exists("unit_tcp") || Exists("missing_plugin") {
		t.Fatal("Exists returned wrong result")
	}
	if got := Get("unit_tcp"); got == nil || got.Name() != "unit_tcp" {
		t.Fatalf("Get(unit_tcp) = %#v", got)
	}
	if got := Get("missing_plugin"); got != nil {
		t.Fatalf("Get(missing_plugin) = %#v, want nil", got)
	}
	if !HasType("unit_tcp", PluginTypeService) || !HasType("unit_local", PluginTypeLocal) {
		t.Fatal("registered plugin types were not recorded")
	}
	if !IsUDP("unit_udp") || IsUDP("unit_tcp") {
		t.Fatal("UDP metadata is wrong")
	}
	if !IsSafe("unit_tcp") || IsSafe("unit_local") || IsSafe("unit_unsafe_web") || IsSafe("missing_plugin") {
		t.Fatal("safe metadata is wrong")
	}

	ports := GetPluginPorts("unit_tcp")
	if len(ports) != 2 || ports[0] != 1234 || ports[1] != 5678 {
		t.Fatalf("ports = %#v", ports)
	}
	if got := GetPluginPorts("missing_plugin"); len(got) != 0 {
		t.Fatalf("missing plugin ports = %#v, want empty", got)
	}
	if !hasPluginType([]string{PluginTypeWeb, PluginTypeLocal}, PluginTypeLocal) ||
		hasPluginType([]string{PluginTypeWeb}, PluginTypeUDP) {
		t.Fatal("hasPluginType returned wrong result")
	}

	names := All()
	for _, want := range []string{"unit_tcp", "unit_udp", "unit_local", "unit_unsafe_web"} {
		if !containsPluginName(names, want) {
			t.Fatalf("All() missing %q in %#v", want, names)
		}
	}
}

func TestPluginLocalModeHook(t *testing.T) {
	preservePluginRegistry(t)

	RegisterWithTypes("unit_local_mode", func() Plugin {
		return testPlugin{BasePlugin: NewBasePlugin("unit_local_mode")}
	}, nil, []string{PluginTypeLocal})
	RegisterWithPorts("unit_service_mode", func() Plugin {
		return testPlugin{BasePlugin: NewBasePlugin("unit_service_mode")}
	}, []int{22})

	if common.IsLocalMode == nil {
		t.Fatal("IsLocalMode hook should be installed")
	}
	if !common.IsLocalMode("unit_local_mode") {
		t.Fatal("single local plugin should be local mode")
	}
	if !common.IsLocalMode("unit_local_mode, unit_local_mode") {
		t.Fatal("local plugin list should be local mode")
	}
	if common.IsLocalMode("") || common.IsLocalMode("all") || common.IsLocalMode("unit_local_mode,unit_service_mode") {
		t.Fatal("non-local modes should not be local mode")
	}
}

func containsPluginName(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestGenerateCredentials_UserPassPairs_Priority(t *testing.T) {
	/*
	   关键测试：UserPassPairs 应该优先于笛卡尔积

	   为什么重要：
	   - UserPassPairs 是用户精确指定的凭据对
	   - 不应该和 Userdict/Passwords 混合使用
	   - 避免生成大量无用凭据

	   Bug 场景：
	   - UserPassPairs + 笛卡尔积混用 → 凭据爆炸
	   - 忽略 UserPassPairs → 用户指定的凭据不生效
	*/

	// 保存原始值
	cfg := common.GetGlobalConfig()
	origUserPassPairs := cfg.Credentials.UserPassPairs
	origUserdict := cfg.Credentials.Userdict
	origPasswords := cfg.Credentials.Passwords
	defer func() {
		cfg.Credentials.UserPassPairs = origUserPassPairs
		cfg.Credentials.Userdict = origUserdict
		cfg.Credentials.Passwords = origPasswords
	}()

	// 设置测试数据
	cfg.Credentials.UserPassPairs = []config.CredentialPair{
		{Username: "admin", Password: "Admin@123"},
		{Username: "root", Password: "Root@456"},
	}

	// 即使有 Userdict 和 Passwords，也应该被忽略
	cfg.Credentials.Userdict = map[string][]string{
		"mysql": {"mysql", "user1", "user2"},
	}
	cfg.Credentials.Passwords = []string{"pass1", "pass2", "pass3"}

	result := GenerateCredentials("mysql", cfg)

	// 验证：只有 2 个凭据（来自 UserPassPairs）
	if len(result) != 2 {
		t.Errorf("Expected 2 credentials from UserPassPairs, got %d", len(result))
	}

	// 验证：凭据内容正确
	expected := map[string]string{
		"admin": "Admin@123",
		"root":  "Root@456",
	}

	for _, cred := range result {
		if expectedPass, exists := expected[cred.Username]; exists {
			if cred.Password != expectedPass {
				t.Errorf("Username %s: expected password %s, got %s",
					cred.Username, expectedPass, cred.Password)
			}
		} else {
			t.Errorf("Unexpected username: %s", cred.Username)
		}
	}

	t.Logf("✓ UserPassPairs 优先: 生成 %d 个精确凭据对", len(result))
}

func TestGenerateCredentials_CartesianProduct(t *testing.T) {
	/*
	   关键测试：笛卡尔积应该正确生成 users × passwords

	   为什么重要：
	   - 笛卡尔积是默认的凭据生成方式
	   - 逻辑错误会导致漏掉有效凭据

	   Bug 场景：
	   - 嵌套循环顺序错误
	   - 重复生成凭据
	   - 遗漏某些组合
	*/

	// 保存原始值
	cfg := common.GetGlobalConfig()
	origUserPassPairs := cfg.Credentials.UserPassPairs
	origUserdict := cfg.Credentials.Userdict
	origPasswords := cfg.Credentials.Passwords
	defer func() {
		cfg.Credentials.UserPassPairs = origUserPassPairs
		cfg.Credentials.Userdict = origUserdict
		cfg.Credentials.Passwords = origPasswords
	}()

	// 清空 UserPassPairs，使用笛卡尔积
	cfg.Credentials.UserPassPairs = []config.CredentialPair{}

	cfg.Credentials.Userdict = map[string][]string{
		"ssh": {"root", "admin"},
	}
	cfg.Credentials.Passwords = []string{"123456", "password"}

	result := GenerateCredentials("ssh", cfg)

	// 验证：应该有 2 × 2 = 4 个凭据
	expected := 2 * 2
	if len(result) != expected {
		t.Errorf("Expected %d credentials (2 users × 2 passwords), got %d", expected, len(result))
	}

	// 验证：所有组合都存在
	expectedCombos := map[string]string{
		"root:123456":    "root",
		"root:password":  "root",
		"admin:123456":   "admin",
		"admin:password": "admin",
	}

	found := make(map[string]bool)
	for _, cred := range result {
		combo := cred.Username + ":" + cred.Password
		found[combo] = true
	}

	for combo := range expectedCombos {
		if !found[combo] {
			t.Errorf("Missing combination: %s", combo)
		}
	}

	t.Logf("✓ 笛卡尔积正确: 2 users × 2 passwords = %d 凭据", len(result))
}

func TestGenerateCredentials_PlaceholderReplacement(t *testing.T) {
	/*
	   关键测试：{user} 占位符应该被替换为用户名

	   为什么重要：
	   - 很多服务的默认密码是用户名（如 mysql:mysql）
	   - {user} 占位符是实现这个需求的关键

	   Bug 场景：
	   - {user} 不替换 → 密码字面值是 "{user}"
	   - 替换错误 → 密码是其他用户名
	*/

	// 保存原始值
	cfg := common.GetGlobalConfig()
	origUserPassPairs := cfg.Credentials.UserPassPairs
	origUserdict := cfg.Credentials.Userdict
	origPasswords := cfg.Credentials.Passwords
	defer func() {
		cfg.Credentials.UserPassPairs = origUserPassPairs
		cfg.Credentials.Userdict = origUserdict
		cfg.Credentials.Passwords = origPasswords
	}()

	cfg.Credentials.UserPassPairs = []config.CredentialPair{}

	cfg.Credentials.Userdict = map[string][]string{
		"mysql": {"root", "mysql"},
	}
	cfg.Credentials.Passwords = []string{"{user}", "{user}123"}

	result := GenerateCredentials("mysql", cfg)

	// 验证：应该有 2 × 2 = 4 个凭据
	expected := 2 * 2
	if len(result) != expected {
		t.Errorf("Expected %d credentials, got %d", expected, len(result))
	}

	// 验证：{user} 被正确替换
	expectedCombos := map[string]string{
		"root:root":      "root",  // {user} → root
		"root:root123":   "root",  // {user}123 → root123
		"mysql:mysql":    "mysql", // {user} → mysql
		"mysql:mysql123": "mysql", // {user}123 → mysql123
	}

	found := make(map[string]bool)
	for _, cred := range result {
		combo := cred.Username + ":" + cred.Password
		found[combo] = true

		// 验证：密码中不应该有字面值 "{user}"
		if cred.Password == "{user}" || cred.Password == "{user}123" {
			t.Errorf("Placeholder not replaced: %s:%s", cred.Username, cred.Password)
		}
	}

	for combo := range expectedCombos {
		if !found[combo] {
			t.Errorf("Missing combination: %s", combo)
		}
	}

	t.Logf("✓ {user} 占位符正确替换: 生成 %d 个凭据", len(result))
}

func TestGenerateCredentials_DefaultValues(t *testing.T) {
	/*
	   关键测试：空字典时应该使用默认值

	   为什么重要：
	   - 某些服务可能没有预定义字典
	   - 空字典不应该导致零凭据

	   Bug 场景：
	   - 空字典 → 零凭据 → 完全不测试
	   - 默认值错误 → 浪费时间测试无用凭据
	*/

	// 保存原始值
	cfg := common.GetGlobalConfig()
	origUserPassPairs := cfg.Credentials.UserPassPairs
	origUserdict := cfg.Credentials.Userdict
	origPasswords := cfg.Credentials.Passwords
	defer func() {
		cfg.Credentials.UserPassPairs = origUserPassPairs
		cfg.Credentials.Userdict = origUserdict
		cfg.Credentials.Passwords = origPasswords
	}()

	cfg.Credentials.UserPassPairs = []config.CredentialPair{}
	cfg.Credentials.Userdict = map[string][]string{} // 空字典
	cfg.Credentials.Passwords = []string{}           // 空密码列表

	result := GenerateCredentials("unknown_service", cfg)

	// 验证：应该有默认凭据
	// 默认用户: admin, root, administrator, user, guest, ""（6个）
	// 默认密码: "", admin, root, password, 123456（5个）
	// 预期：6 × 5 = 30 个凭据
	expectedUsers := []string{"admin", "root", "administrator", "user", "guest", ""}
	expectedPasswords := []string{"", "admin", "root", "password", "123456"}
	expectedTotal := len(expectedUsers) * len(expectedPasswords)

	if len(result) != expectedTotal {
		t.Errorf("Expected %d credentials with default values, got %d", expectedTotal, len(result))
	}

	// 验证：默认用户和密码都被使用
	usersFound := make(map[string]bool)
	passwordsFound := make(map[string]bool)

	for _, cred := range result {
		usersFound[cred.Username] = true
		passwordsFound[cred.Password] = true
	}

	for _, user := range expectedUsers {
		if !usersFound[user] {
			t.Errorf("Default user not found: %s", user)
		}
	}

	for _, pass := range expectedPasswords {
		if !passwordsFound[pass] {
			t.Errorf("Default password not found: %s", pass)
		}
	}

	t.Logf("✓ 默认值正确: %d users × %d passwords = %d 凭据",
		len(expectedUsers), len(expectedPasswords), len(result))
}

func TestGenerateCredentials_EmptyUserPassPairs(t *testing.T) {
	/*
	   关键测试：空的 UserPassPairs 应该回退到笛卡尔积

	   为什么重要：
	   - UserPassPairs = [] 和 nil 行为应该一致
	   - 避免特殊情况

	   Bug 场景：
	   - 空数组被当作"有值" → 生成零凭据
	*/

	// 保存原始值
	cfg := common.GetGlobalConfig()
	origUserPassPairs := cfg.Credentials.UserPassPairs
	origUserdict := cfg.Credentials.Userdict
	origPasswords := cfg.Credentials.Passwords
	defer func() {
		cfg.Credentials.UserPassPairs = origUserPassPairs
		cfg.Credentials.Userdict = origUserdict
		cfg.Credentials.Passwords = origPasswords
	}()

	cfg.Credentials.UserPassPairs = []config.CredentialPair{} // 空数组
	cfg.Credentials.Userdict = map[string][]string{
		"test": {"user1"},
	}
	cfg.Credentials.Passwords = []string{"pass1"}

	result := GenerateCredentials("test", cfg)

	// 验证：应该回退到笛卡尔积（1 × 1 = 1）
	if len(result) != 1 {
		t.Errorf("Expected 1 credential (fallback to cartesian), got %d", len(result))
	}

	if result[0].Username != "user1" || result[0].Password != "pass1" {
		t.Errorf("Expected user1:pass1, got %s:%s", result[0].Username, result[0].Password)
	}

	t.Logf("✓ 空 UserPassPairs 正确回退到笛卡尔积")
}

func TestBuildConfigAdditionalPasswordsAreNotShadowedByExactPair(t *testing.T) {
	cfg, _, err := common.BuildConfig(&common.FlagVars{
		Username:     "root",
		Password:     "primary",
		AddPasswords: "extra",
	}, &common.HostInfo{})
	if err != nil {
		t.Fatalf("BuildConfig error = %v", err)
	}

	result := GenerateCredentials("ssh", cfg)
	found := map[string]bool{}
	for _, cred := range result {
		found[cred.Username+":"+cred.Password] = true
	}

	if !found["root:primary"] {
		t.Fatal("missing primary password credential")
	}
	if !found["root:extra"] {
		t.Fatal("additional password was shadowed by exact user/password pair")
	}
}
