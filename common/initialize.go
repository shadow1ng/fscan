package common

import (
	"fmt"
)

/*
initialize.go - 统一初始化入口

简化后的流程：
命令行 → FlagVars → BuildConfig() → Config + State
*/

// InitResult 初始化结果
type InitResult struct {
	Config  *Config
	State   *State
	Info    *HostInfo
	Session *ScanSession
}

// Initialize 统一初始化函数
// 封装 BuildConfig → InitOutput 流程
func Initialize(info *HostInfo) (*InitResult, error) {
	// 1. 初始化日志系统
	InitLogger()

	// 2. 从 FlagVars 构建 Config 和 State
	cfg, state, err := BuildConfig(GetFlagVars(), info)
	if err != nil {
		return nil, fmt.Errorf("配置构建失败: %w", err)
	}

	// 3. 设置全局实例
	SetGlobalConfig(cfg)
	SetGlobalState(state)

	// 4. 初始化输出系统
	if err := InitOutput(); err != nil {
		return nil, fmt.Errorf("输出初始化失败: %w", err)
	}

	session := NewScanSession(cfg, state, GetFlagVars())

	return &InitResult{
		Config:  cfg,
		State:   state,
		Info:    info,
		Session: session,
	}, nil
}

// ValidateExclusiveParams 验证互斥参数
// 检查 -h、-u、-local 只能指定一个
func ValidateExclusiveParams(info *HostInfo) error {
	paramCount := 0
	var activeParam string

	fv := GetFlagVars()

	if info.Host != "" {
		paramCount++
		activeParam = "-h"
	}
	if fv.TargetURL != "" {
		paramCount++
		if activeParam != "" {
			activeParam += " 和 -u"
		} else {
			activeParam = "-u"
		}
	}
	if fv.LocalPlugin != "" {
		paramCount++
		if activeParam != "" {
			activeParam += " 和 -local"
		} else {
			activeParam = "-local"
		}
	}

	if paramCount > 1 {
		return fmt.Errorf("参数 %s 互斥，请只指定一个扫描目标\n  -h: 网络主机扫描\n  -u: Web URL扫描\n  -local: 本地信息收集", activeParam)
	}

	return nil
}

// Cleanup 清理资源
func Cleanup() error {
	return CloseOutput()
}
