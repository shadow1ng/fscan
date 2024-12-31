package lib

import (
	"context"
	"crypto/tls"
	"embed"
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// 全局HTTP客户端变量
var (
	Client           *http.Client      // 标准HTTP客户端
	ClientNoRedirect *http.Client      // 不自动跟随重定向的HTTP客户端
	dialTimout       = 5 * time.Second // 连接超时时间
	keepAlive        = 5 * time.Second // 连接保持时间
)

// Inithttp 初始化HTTP客户端配置
func Inithttp() {
	// 设置默认并发数
	if Common.PocNum == 0 {
		Common.PocNum = 20
	}
	// 设置默认超时时间
	if Common.WebTimeout == 0 {
		Common.WebTimeout = 5
	}

	// 初始化HTTP客户端
	err := InitHttpClient(Common.PocNum, Common.HttpProxy, time.Duration(Common.WebTimeout)*time.Second)
	if err != nil {
		panic(err)
	}
}

// InitHttpClient 创建HTTP客户端
func InitHttpClient(ThreadsNum int, DownProxy string, Timeout time.Duration) error {
	type DialContext = func(ctx context.Context, network, addr string) (net.Conn, error)

	// 配置基础连接参数
	dialer := &net.Dialer{
		Timeout:   dialTimout,
		KeepAlive: keepAlive,
	}

	// 配置Transport参数
	tr := &http.Transport{
		DialContext:         dialer.DialContext,
		MaxConnsPerHost:     5,
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: ThreadsNum * 2,
		IdleConnTimeout:     keepAlive,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS10, InsecureSkipVerify: true},
		TLSHandshakeTimeout: 5 * time.Second,
		DisableKeepAlives:   false,
	}

	// 配置Socks5代理
	if Common.Socks5Proxy != "" {
		dialSocksProxy, err := Common.Socks5Dialer(dialer)
		if err != nil {
			return err
		}
		if contextDialer, ok := dialSocksProxy.(proxy.ContextDialer); ok {
			tr.DialContext = contextDialer.DialContext
		} else {
			return errors.New("无法转换为DialContext类型")
		}
	} else if DownProxy != "" {
		// 处理其他代理配置
		if DownProxy == "1" {
			DownProxy = "http://127.0.0.1:8080"
		} else if DownProxy == "2" {
			DownProxy = "socks5://127.0.0.1:1080"
		} else if !strings.Contains(DownProxy, "://") {
			DownProxy = "http://127.0.0.1:" + DownProxy
		}

		// 验证代理类型
		if !strings.HasPrefix(DownProxy, "socks") && !strings.HasPrefix(DownProxy, "http") {
			return errors.New("不支持的代理类型")
		}

		// 解析代理URL
		u, err := url.Parse(DownProxy)
		if err != nil {
			return err
		}
		tr.Proxy = http.ProxyURL(u)
	}

	// 创建标准HTTP客户端
	Client = &http.Client{
		Transport: tr,
		Timeout:   Timeout,
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

// 自定义映射类型
type (
	StrMap  []StrItem  // 字符串键值对映射
	ListMap []ListItem // 字符串键列表值映射
	RuleMap []RuleItem // 字符串键规则列表映射
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
		key, value := one.Key.(string), one.Value.(string)
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
		key := one.Key.(string)
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
		key := one.Key.(string)
		var value []string
		// 将接口类型转换为字符串
		for _, val := range one.Value.([]interface{}) {
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
			fmt.Printf("POC加载失败 %s: %v\n", f, err)
		}
	}
	return pocs
}

// LoadPoc 从内嵌文件系统加载单个POC
func LoadPoc(fileName string, Pocs embed.FS) (*Poc, error) {
	p := &Poc{}
	// 读取POC文件内容
	yamlFile, err := Pocs.ReadFile("pocs/" + fileName)
	if err != nil {
		fmt.Printf("POC文件读取失败 %s: %v\n", fileName, err)
		return nil, err
	}

	// 解析YAML内容
	err = yaml.Unmarshal(yamlFile, p)
	if err != nil {
		fmt.Printf("POC解析失败 %s: %v\n", fileName, err)
		return nil, err
	}
	return p, err
}

// SelectPoc 根据名称关键字选择POC文件
func SelectPoc(Pocs embed.FS, pocname string) []string {
	entries, err := Pocs.ReadDir("pocs")
	if err != nil {
		fmt.Printf("读取POC目录失败: %v\n", err)
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
	p := &Poc{}
	// 读取POC文件内容
	data, err := os.ReadFile(fileName)
	if err != nil {
		fmt.Printf("POC文件读取失败 %s: %v\n", fileName, err)
		return nil, err
	}

	// 解析YAML内容
	err = yaml.Unmarshal(data, p)
	if err != nil {
		fmt.Printf("POC解析失败 %s: %v\n", fileName, err)
		return nil, err
	}
	return p, err
}
