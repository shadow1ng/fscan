package plugins

import (
	"context"
	"strings"
	"sync"

	"github.com/shadow1ng/fscan/common"
)

// Plugin 统一插件接口
type Plugin interface {
	Name() string
	Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *Result
}

// BasePlugin 基础插件结构，提供通用的name字段
type BasePlugin struct {
	name string
}

// NewBasePlugin 创建基础插件
func NewBasePlugin(name string) BasePlugin {
	return BasePlugin{name: name}
}

// Name 实现Plugin接口
func (b BasePlugin) Name() string {
	return b.name
}

// ResultType 结果类型
type ResultType string

const (
	ResultTypeCredential ResultType = "credential" // 弱密码发现
	ResultTypeService    ResultType = "service"    // 服务识别
	ResultTypeVuln       ResultType = "vuln"       // 漏洞发现
	ResultTypeWeb        ResultType = "web"        // Web识别
)

// Result 统一结果结构
type Result struct {
	Type     ResultType
	Success  bool
	Skipped  bool   // 扫描被跳过，不应输出结果
	Service  string
	Username string
	Password string
	Banner   string
	Output   string // web/local插件使用
	Error    error

	// Web插件字段
	Title        string   // 网页标题
	Status       int      // HTTP状态码
	Server       string   // 服务器信息
	Length       int      // 响应长度
	VulInfo      string   // 漏洞信息
	Fingerprints []string // 指纹信息
}

// Exploiter 利用接口
type Exploiter interface {
	Exploit(ctx context.Context, info *common.HostInfo, creds Credential, session *common.ScanSession) *ExploitResult
}

// ExploitResult 利用结果
type ExploitResult struct {
	Success bool
	Output  string
	Error   error
}

// Credential 认证凭据
type Credential struct {
	Username string
	Password string
	KeyData  []byte
}

// PluginInfo 插件信息结构
type PluginInfo struct {
	factory func() Plugin
	ports   []int
	types   []string // 插件类型标签
}

// 插件类型常量
const (
	PluginTypeWeb     = "web"     // Web类型插件
	PluginTypeLocal   = "local"   // 本地类型插件
	PluginTypeService = "service" // 服务类型插件
)

var (
	plugins = make(map[string]*PluginInfo)
	mutex   sync.RWMutex
)

// RegisterWithPorts 注册带端口信息的插件
func RegisterWithPorts(name string, factory func() Plugin, ports []int) {
	RegisterWithTypes(name, factory, ports, []string{PluginTypeService})
}

// RegisterWithTypes 注册带类型标签的插件
func RegisterWithTypes(name string, factory func() Plugin, ports []int, types []string) {
	mutex.Lock()
	defer mutex.Unlock()
	plugins[name] = &PluginInfo{
		factory: factory,
		ports:   ports,
		types:   types,
	}
}

// HasType 检查插件是否具有指定类型
func HasType(pluginName string, typeName string) bool {
	mutex.RLock()
	defer mutex.RUnlock()

	if info, exists := plugins[pluginName]; exists {
		for _, t := range info.types {
			if t == typeName {
				return true
			}
		}
	}
	return false
}

// Get 获取插件实例
func Get(name string) Plugin {
	mutex.RLock()
	defer mutex.RUnlock()

	if info, exists := plugins[name]; exists {
		return info.factory()
	}
	return nil
}

// All 获取所有插件名称
func All() []string {
	mutex.RLock()
	defer mutex.RUnlock()

	names := make([]string, 0, len(plugins))
	for name := range plugins {
		names = append(names, name)
	}
	return names
}

// Exists 检查插件是否存在
func Exists(name string) bool {
	mutex.RLock()
	defer mutex.RUnlock()

	_, exists := plugins[name]
	return exists
}

// GetPluginPorts 获取插件端口列表
func GetPluginPorts(name string) []int {
	mutex.RLock()
	defer mutex.RUnlock()

	if info, exists := plugins[name]; exists {
		return info.ports
	}
	return []int{} // 返回空列表表示适用于所有端口
}

// GenerateCredentials 生成测试凭据
func GenerateCredentials(service string, config *common.Config) []Credential {
	var credentials []Credential
	credConfig := config.Credentials

	// 优先使用精确的用户密码对
	if len(credConfig.UserPassPairs) > 0 {
		for _, pair := range credConfig.UserPassPairs {
			credentials = append(credentials, Credential{
				Username: pair.Username,
				Password: pair.Password,
			})
		}
		return credentials
	}

	// 否则使用笛卡尔积方式
	users := credConfig.Userdict[service]
	if len(users) == 0 {
		users = []string{"admin", "root", "administrator", "user", "guest", ""}
	}

	passwords := credConfig.Passwords
	if len(passwords) == 0 {
		passwords = []string{"", "admin", "root", "password", "123456"}
	}

	for _, user := range users {
		for _, pass := range passwords {
			actualPass := strings.ReplaceAll(pass, "{user}", user)
			credentials = append(credentials, Credential{
				Username: user,
				Password: actualPass,
			})
		}
	}
	return credentials
}
