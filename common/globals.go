package common

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

/*
globals.go - 全局配置变量

运行时数据和必要的全局状态。
命令行参数现通过 GetFlagVars() 访问，配置通过 GetGlobalConfig() 访问。
*/

// =============================================================================
// 核心数据结构
// =============================================================================

// HostInfo 主机信息结构 - 最核心的数据结构
type HostInfo struct {
	Host string   // 主机地址
	Port int      // 端口号（单个端口）
	URL  string   // URL地址
	Info []string // 附加信息
}

// Target 返回 host:port 格式字符串
func (h *HostInfo) Target() string {
	return fmt.Sprintf("%s:%d", h.Host, h.Port)
}

// =============================================================================
// 默认配置常量
// =============================================================================

const (
	// DefaultThreadNum 默认线程数
	DefaultThreadNum = 600
	// DefaultTimeout 默认超时时间(秒)
	DefaultTimeout = 3
	// DefaultScanMode 默认扫描模式
	DefaultScanMode = "all"
	// DefaultLanguage 默认语言
	DefaultLanguage = "zh"
	// DefaultLogLevel 默认日志级别
	DefaultLogLevel = "base"
)

// 日志级别常量
const (
	LogLevelAll             = "all"
	LogLevelError           = "error"
	LogLevelBase            = "base"
	LogLevelInfo            = "info"
	LogLevelSuccess         = "success"
	LogLevelDebug           = "debug"
	LogLevelInfoSuccess     = "info,success"
	LogLevelBaseInfoSuccess = "base,info,success"
)

// 版本信息，通过 ldflags 注入
var (
	version = "2.1.3"
	commit  = "unknown"
	date    = "unknown"
)

// 运行时数据已迁移到Config对象中，使用GetGlobalConfig()访问

// Shell状态已迁移到State对象中，使用GetGlobalState()访问

// POC配置、输出控制、发包控制、初始化已迁移到Config/State对象中

// =============================================================================
// 发包限制错误类型
// =============================================================================

// 哨兵错误 - 用于 errors.Is 判断
var (
	ErrMaxPacketReached  = errors.New("max packet count reached")
	ErrPacketRateLimited = errors.New("packet rate limited")
)

// PacketLimitError 发包限制错误（包含详情）
type PacketLimitError struct {
	Sentinel error // ErrMaxPacketReached 或 ErrPacketRateLimited
	Limit    int64
	Current  int64
}

func (e *PacketLimitError) Error() string {
	if e.Sentinel == ErrMaxPacketReached {
		return fmt.Sprintf("已达到最大发包数量限制: %d", e.Limit)
	}
	return fmt.Sprintf("发包速率受限: %d包/分钟", e.Limit)
}

func (e *PacketLimitError) Unwrap() error {
	return e.Sentinel
}

// =============================================================================
// 发包频率控制功能
// =============================================================================

// CanSendPacketWith 检查是否可以发包 - 同时检查频率限制和总数限制
// 返回值: (可以发包, 错误)
func CanSendPacketWith(config *Config, state *State) (bool, error) {
	// 检查总数限制
	maxPacketCount := config.Network.MaxPacketCount
	if maxPacketCount > 0 {
		currentTotal := state.GetPacketCount()
		if currentTotal >= maxPacketCount {
			return false, &PacketLimitError{
				Sentinel: ErrMaxPacketReached,
				Limit:    maxPacketCount,
				Current:  currentTotal,
			}
		}
	}

	// 检查频率限制
	return state.CheckAndIncrementPacketRate(config.Network.PacketRateLimit)
}

// CanSendPacket 便捷API - 使用全局配置和状态
// 内部调用 CanSendPacketWith，保持向后兼容（返回string）
func CanSendPacket() (bool, string) {
	ok, err := CanSendPacketWith(GetGlobalConfig(), GetGlobalState())
	if err != nil {
		return ok, err.Error()
	}
	return ok, ""
}

// =============================================================================
// 全局 Config 和 State 实例（新架构）
// =============================================================================

var (
	// globalConfig 全局配置实例（小写，不直接暴露）
	globalConfig *Config

	// globalState 全局状态实例（小写，不直接暴露）
	globalState *State

	// globalMu 保护全局变量的读写锁
	globalMu sync.RWMutex
)

// GetGlobalConfig 获取全局配置实例（线程安全）
// 使用读写锁保护，避免竞态条件
func GetGlobalConfig() *Config {
	globalMu.RLock()
	cfg := globalConfig
	globalMu.RUnlock()

	if cfg != nil {
		return cfg
	}

	// 需要初始化，获取写锁
	globalMu.Lock()
	defer globalMu.Unlock()

	// 双重检查，避免重复初始化
	if globalConfig == nil {
		globalConfig = NewConfig()
	}
	return globalConfig
}

// SetGlobalConfig 设置全局配置实例（线程安全）
func SetGlobalConfig(cfg *Config) {
	globalMu.Lock()
	globalConfig = cfg
	globalMu.Unlock()
}

// GetGlobalState 获取全局状态实例（线程安全）
// 使用读写锁保护，避免竞态条件
func GetGlobalState() *State {
	globalMu.RLock()
	st := globalState
	globalMu.RUnlock()

	if st != nil {
		return st
	}

	// 需要初始化，获取写锁
	globalMu.Lock()
	defer globalMu.Unlock()

	// 双重检查，避免重复初始化
	if globalState == nil {
		globalState = NewState()
	}
	return globalState
}

// SetGlobalState 设置全局状态实例（线程安全）
func SetGlobalState(state *State) {
	globalMu.Lock()
	globalState = state
	globalMu.Unlock()
}

// =============================================================================
// 字符串工具函数
// =============================================================================

// ContainsAny 检查字符串是否包含任意一个子串
func ContainsAny(s string, substrs ...string) bool {
	for _, substr := range substrs {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}
