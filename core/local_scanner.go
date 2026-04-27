package core

import (
	"context"
	"sync"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// LocalScanStrategy 本地扫描策略
type LocalScanStrategy struct {
	*BaseScanStrategy
}

// NewLocalScanStrategy 创建新的本地扫描策略
func NewLocalScanStrategy() *LocalScanStrategy {
	return &LocalScanStrategy{
		BaseScanStrategy: NewBaseScanStrategy("本地扫描", FilterLocal),
	}
}

// LogPluginInfo 重写以只显示通过-local指定的插件
func (s *LocalScanStrategy) LogPluginInfo(config *common.Config) {
	localPlugin := config.LocalPlugin
	if localPlugin != "" {
		common.LogInfo(i18n.Tr("local_plugin_info", localPlugin))
	} else {
		common.LogError(i18n.GetText("local_plugin_not_specified"))
	}
}

// Name 返回策略名称
func (s *LocalScanStrategy) Name() string {
	return i18n.GetText("scan_strategy_local_name")
}

// Description 返回策略描述
func (s *LocalScanStrategy) Description() string {
	return i18n.GetText("scan_strategy_local_desc")
}

// Execute 执行本地扫描策略
func (s *LocalScanStrategy) Execute(ctx context.Context, session *common.ScanSession, info common.HostInfo, ch chan struct{}, wg *sync.WaitGroup) {
	config := session.Config

	// 输出扫描开始信息
	s.LogScanStart()

	// 验证插件配置
	if err := s.ValidateConfiguration(); err != nil {
		common.LogError(err.Error())
		return
	}

	// 验证本地插件是否存在
	if config.LocalPlugin != "" {
		if !plugins.Exists(config.LocalPlugin) {
			common.LogError(i18n.Tr("local_plugin_not_found", config.LocalPlugin))
			return
		}
	}

	// 输出插件信息
	s.LogPluginInfo(config)

	// 准备目标（本地扫描通常只有一个目标，即本机）
	targets := s.PrepareTargets(info)

	// 执行扫描任务
	ExecuteScanTasks(ctx, session, targets, s, ch, wg)
}

// PrepareTargets 准备本地扫描目标
func (s *LocalScanStrategy) PrepareTargets(info common.HostInfo) []common.HostInfo {
	// 本地扫描只使用传入的目标信息，不做额外处理
	return []common.HostInfo{info}
}
