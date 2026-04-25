package lib

import (
	"crypto/tls"
	"embed"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/proxy"
	"gopkg.in/yaml.v2"
)

const (
	// ProxyShortcutBurp Burp Suite默认代理快捷配置
	ProxyShortcutBurp = "1"
	// ProxyShortcutSocks5 SOCKS5默认代理快捷配置
	ProxyShortcutSocks5 = "2"
	// ProxyBurpURL Burp Suite代理地址
	ProxyBurpURL = "http://127.0.0.1:8080"
	// ProxySocks5URL SOCKS5代理地址
	ProxySocks5URL = "socks5://127.0.0.1:1080"
)

// 全局HTTP客户端变量
var (
	Client           *http.Client      // 标准HTTP客户端
	ClientNoRedirect *http.Client      // 不自动跟随重定向的HTTP客户端
	dialTimeout      = 5 * time.Second // 连接超时时间
	keepAlive        = 5 * time.Second // 连接保持时间
)

// Inithttp 初始化HTTP客户端配置
func Inithttp(cfg *common.Config) error {
	// 获取POC并发数，默认20
	pocNum := cfg.POC.Num
	if pocNum == 0 {
		pocNum = 20
	}

	// 初始化HTTP客户端
	err := InitHTTPClient(pocNum, cfg.Network.HTTPProxy, cfg.Network.WebTimeout, cfg.Network.MaxRedirects, &cfg.Network)
	if err != nil {
		return fmt.Errorf("HTTP客户端初始化失败: %w", err)
	}
	return nil
}

// configureHTTPProxy 统一配置HTTP代理（SOCKS5优先于HTTP代理）
func configureHTTPProxy(tr *http.Transport, legacyProxy string, networkConfig *common.NetworkConfig) error {
	// 优先使用SOCKS5代理（与服务扫描保持一致）
	if networkConfig.Socks5Proxy != "" {
		proxyConfig := &proxy.ProxyConfig{
			Type:    proxy.ProxyTypeSOCKS5,
			Timeout: time.Second * 10,
		}

		// 解析SOCKS5 URL以提取认证信息
		socks5URL := networkConfig.Socks5Proxy
		if !strings.HasPrefix(socks5URL, "socks5://") {
			socks5URL = "socks5://" + socks5URL
		}

		if parsedURL, err := url.Parse(socks5URL); err == nil {
			proxyConfig.Address = parsedURL.Host
			if parsedURL.User != nil {
				proxyConfig.Username = parsedURL.User.Username()
				if password, hasPassword := parsedURL.User.Password(); hasPassword {
					proxyConfig.Password = password
				}
			}
		} else {
			proxyConfig.Address = networkConfig.Socks5Proxy
		}

		proxyManager := proxy.NewProxyManager(proxyConfig)
		proxyDialer, err := proxyManager.GetDialer()
		if err != nil {
			return fmt.Errorf("SOCKS5代理配置失败: %w", err)
		}
		tr.DialContext = proxyDialer.DialContext
		return nil
	}

	// 其次使用HTTP代理（优先级低于SOCKS5）
	httpProxyURL := networkConfig.HTTPProxy
	if httpProxyURL == "" && legacyProxy != "" {
		// 兼容旧参数DownProxy
		httpProxyURL = legacyProxy
	}

	if httpProxyURL != "" {
		// 处理快捷代理配置
		if httpProxyURL == ProxyShortcutBurp {
			httpProxyURL = ProxyBurpURL
		} else if httpProxyURL == ProxyShortcutSocks5 {
			httpProxyURL = ProxySocks5URL
		} else if !strings.Contains(httpProxyURL, "://") {
			httpProxyURL = "http://127.0.0.1:" + httpProxyURL
		}

		// 验证代理类型
		if !strings.HasPrefix(httpProxyURL, "socks5://") && !strings.HasPrefix(httpProxyURL, "http://") && !strings.HasPrefix(httpProxyURL, "https://") {
			return fmt.Errorf("不支持的代理类型: %s", httpProxyURL)
		}

		// 解析代理URL
		parsedURL, err := url.Parse(httpProxyURL)
		if err != nil {
			return fmt.Errorf("代理URL解析失败: %w", err)
		}
		tr.Proxy = http.ProxyURL(parsedURL)
		return nil
	}

	// 无代理配置
	return nil
}

// InitHTTPClient 创建HTTP客户端
func InitHTTPClient(ThreadsNum int, DownProxy string, Timeout time.Duration, maxRedirects int, networkConfig *common.NetworkConfig) error {
	// 配置基础连接参数
	dialer := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: keepAlive,
	}

	// 配置Transport参数
	tr := &http.Transport{
		DialContext:         dialer.DialContext,
		MaxConnsPerHost:     100,                 // 增加到100，避免连接池耗尽
		MaxIdleConns:        100,                 // 保留100个空闲连接
		MaxIdleConnsPerHost: 10,                  // 每主机保留10个空闲连接
		IdleConnTimeout:     keepAlive,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS10, InsecureSkipVerify: true},
		TLSHandshakeTimeout: 5 * time.Second,
		DisableKeepAlives:   false,
	}

	// 统一配置代理
	if err := configureHTTPProxy(tr, DownProxy, networkConfig); err != nil {
		return err
	}

	// 创建标准HTTP客户端（限制重定向次数）
	Client = &http.Client{
		Transport: tr,
		Timeout:   Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return http.ErrUseLastResponse // 达到限制，使用最后响应
			}
			return nil // 继续跟随
		},
	}

	// 创建不跟随重定向的HTTP客户端
	ClientNoRedirect = &http.Client{
		Transport:     tr,
		Timeout:       Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}

	return nil
}

// Poc 定义漏洞检测配置结构
type Poc struct {
	Name   string  `yaml:"name"`   // POC名称
	Set    StrMap  `yaml:"set"`    // 单值配置映射
	Sets   ListMap `yaml:"sets"`   // 列表值配置映射
	Rules  []Rules `yaml:"rules"`  // 检测规则列表
	Groups RuleMap `yaml:"groups"` // 规则组映射
	Detail Detail  `yaml:"detail"` // 漏洞详情
}

// MapSlice 用于解析YAML的通用映射类型
type MapSlice = yaml.MapSlice

// StrMap 字符串键值对映射（自定义映射类型）
type (
	StrMap []StrItem
	// ListMap 字符串键列表值映射
	ListMap []ListItem
	// RuleMap 字符串键规则列表映射
	RuleMap []RuleItem
)

// 映射项结构定义
type (
	// StrItem 字符串键值对
	StrItem struct {
		Key   string // 键名
		Value string // 值
	}

	// ListItem 字符串键列表值对
	ListItem struct {
		Key   string   // 键名
		Value []string // 值列表
	}

	// RuleItem 字符串键规则列表对
	RuleItem struct {
		Key   string  // 键名
		Value []Rules // 规则列表
	}
)

// UnmarshalYAML 实现StrMap的YAML解析接口
func (r *StrMap) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// 临时使用MapSlice存储解析结果
	var tmp yaml.MapSlice
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	// 转换为StrMap结构
	for _, one := range tmp {
		key, keyOk := one.Key.(string)
		value, valueOk := one.Value.(string)
		if !keyOk || !valueOk {
			return fmt.Errorf("StrMap解析失败: 键或值不是字符串类型")
		}
		*r = append(*r, StrItem{key, value})
	}

	return nil
}

// UnmarshalYAML 实现RuleMap的YAML解析接口
// 参数：
//   - unmarshal: YAML解析函数
//
// 返回：
//   - error: 解析错误
func (r *RuleMap) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// 使用MapSlice保持键的顺序
	var tmp1 yaml.MapSlice
	if err := unmarshal(&tmp1); err != nil {
		return err
	}

	// 解析规则内容
	var tmp = make(map[string][]Rules)
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	// 按顺序转换为RuleMap结构
	for _, one := range tmp1 {
		key, ok := one.Key.(string)
		if !ok {
			return fmt.Errorf("RuleMap解析失败: 键不是字符串类型")
		}
		value := tmp[key]
		*r = append(*r, RuleItem{key, value})
	}
	return nil
}

// UnmarshalYAML 实现ListMap的YAML解析接口
// 参数：
//   - unmarshal: YAML解析函数
//
// 返回：
//   - error: 解析错误
func (r *ListMap) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// 解析YAML映射
	var tmp yaml.MapSlice
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	// 转换为ListMap结构
	for _, one := range tmp {
		key, keyOk := one.Key.(string)
		if !keyOk {
			return fmt.Errorf("ListMap解析失败: 键不是字符串类型")
		}

		valueSlice, valueOk := one.Value.([]interface{})
		if !valueOk {
			return fmt.Errorf("ListMap解析失败: 值不是数组类型")
		}

		var value []string
		// 将接口类型转换为字符串
		for _, val := range valueSlice {
			v := fmt.Sprintf("%v", val)
			value = append(value, v)
		}
		*r = append(*r, ListItem{key, value})
	}
	return nil
}

// Rules 定义POC检测规则结构
type Rules struct {
	Method          string            `yaml:"method"`           // HTTP请求方法
	Path            string            `yaml:"path"`             // 请求路径
	Headers         map[string]string `yaml:"headers"`          // 请求头
	Body            string            `yaml:"body"`             // 请求体
	Search          string            `yaml:"search"`           // 搜索模式
	FollowRedirects bool              `yaml:"follow_redirects"` // 是否跟随重定向
	Expression      string            `yaml:"expression"`       // 匹配表达式
	Continue        bool              `yaml:"continue"`         // 是否继续执行
}

// Detail 定义POC详情结构
type Detail struct {
	Author      string   `yaml:"author"`      // POC作者
	Links       []string `yaml:"links"`       // 相关链接
	Description string   `yaml:"description"` // POC描述
	Version     string   `yaml:"version"`     // POC版本
}

// LoadMultiPoc 加载多个POC文件
func LoadMultiPoc(Pocs embed.FS, pocname string) []*Poc {
	var pocs []*Poc
	// 遍历选中的POC文件
	for _, f := range SelectPoc(Pocs, pocname) {
		if p, err := LoadPoc(f, Pocs); err == nil {
			pocs = append(pocs, p)
		} else {
			common.LogError(fmt.Sprintf("POC加载失败 %s: %v", f, err))
		}
	}
	return pocs
}

// parsePocYAML 解析POC YAML内容（提取公共逻辑）
func parsePocYAML(data []byte, fileName string) (*Poc, error) {
	// 使用通用适配器加载POC（自动识别格式）
	universalPoc, err := LoadUniversalPoc(fileName, data)
	if err != nil {
		return nil, fmt.Errorf("POC解析失败 %s: %w", fileName, err)
	}

	// 转换为fscan内部格式
	poc, err := universalPoc.ToFscanPoc()
	if err != nil {
		return nil, fmt.Errorf("POC格式转换失败 %s: %w", fileName, err)
	}

	return poc, nil
}

// LoadPoc 从内嵌文件系统加载单个POC
func LoadPoc(fileName string, Pocs embed.FS) (*Poc, error) {
	// 读取POC文件内容
	yamlFile, err := Pocs.ReadFile("pocs/" + fileName)
	if err != nil {
		return nil, fmt.Errorf("POC文件读取失败 %s: %w", fileName, err)
	}

	// 解析YAML内容
	return parsePocYAML(yamlFile, fileName)
}

// SelectPoc 根据名称关键字选择POC文件
func SelectPoc(Pocs embed.FS, pocname string) []string {
	entries, err := Pocs.ReadDir("pocs")
	if err != nil {
		common.LogError(fmt.Sprintf("读取POC目录失败: %v", err))
	}

	var foundFiles []string
	// 查找匹配关键字的POC文件
	for _, entry := range entries {
		if strings.Contains(entry.Name(), pocname) {
			foundFiles = append(foundFiles, entry.Name())
		}
	}
	return foundFiles
}

// LoadPocbyPath 从文件系统路径加载POC
func LoadPocbyPath(fileName string) (*Poc, error) {
	// 读取POC文件内容
	data, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("POC文件读取失败 %s: %w", fileName, err)
	}

	// 解析YAML内容
	return parsePocYAML(data, fileName)
}
