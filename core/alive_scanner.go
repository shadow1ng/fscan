package core

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/common/parsers"
)

/*
AliveScanner.go - 存活探测扫描器

专门用于主机存活探测，仅执行ICMP/Ping检测，
快速识别网络中的存活主机，不进行端口扫描。
*/

// AliveScanStrategy 存活探测扫描策略
type AliveScanStrategy struct {
	*BaseScanStrategy
	startTime time.Time
	stats     AliveStats
}

// AliveStats 存活探测统计信息
type AliveStats struct {
	TotalHosts    int           // 总主机数
	AliveHosts    int           // 存活主机数
	DeadHosts     int           // 死亡主机数
	ScanDuration  time.Duration // 扫描耗时
	SuccessRate   float64       // 成功率
	AliveHostList []string      // 存活主机列表
}

// NewAliveScanStrategy 创建新的存活探测扫描策略
func NewAliveScanStrategy() *AliveScanStrategy {
	return &AliveScanStrategy{
		BaseScanStrategy: NewBaseScanStrategy("存活探测", FilterNone),
		startTime:        time.Now(),
	}
}

// Name 返回策略名称
func (s *AliveScanStrategy) Name() string {
	return i18n.GetText("scan_strategy_alive_name")
}

// Description 返回策略描述
func (s *AliveScanStrategy) Description() string {
	return i18n.GetText("scan_strategy_alive_desc")
}

// Execute 执行存活探测扫描策略
func (s *AliveScanStrategy) Execute(ctx context.Context, session *common.ScanSession, info common.HostInfo, ch chan struct{}, wg *sync.WaitGroup) {
	// 验证扫描目标（需要同时检查 -h 和 -hf 参数）
	if info.Host == "" && session.Params.HostsFile == "" {
		common.LogError(i18n.GetText("parse_error_target_empty"))
		return
	}

	// 执行存活探测
	s.performAliveScan(ctx, info, session)

	// 输出统计信息
	s.outputStats()
}

// performAliveScan 执行存活探测
func (s *AliveScanStrategy) performAliveScan(ctx context.Context, info common.HostInfo, session *common.ScanSession) {
	// 解析目标主机
	hosts, err := parsers.ParseIP(info.Host, session.Params.HostsFile, session.Params.ExcludeHosts)
	if err != nil {
		common.LogError(i18n.Tr("parse_target_failed", err))
		return
	}

	if len(hosts) == 0 {
		common.LogError(i18n.GetText("parse_error_no_hosts"))
		return
	}

	// 初始化统计信息
	s.stats.TotalHosts = len(hosts)
	s.stats.AliveHosts = 0
	s.stats.DeadHosts = 0


	// 执行存活检测
	aliveList := CheckLive(ctx, hosts, false, session) // 使用ICMP探测

	// 更新统计信息
	s.stats.AliveHosts = len(aliveList)
	s.stats.DeadHosts = s.stats.TotalHosts - s.stats.AliveHosts
	s.stats.ScanDuration = time.Since(s.startTime)
	s.stats.AliveHostList = aliveList // 存储存活主机列表

	if s.stats.TotalHosts > 0 {
		s.stats.SuccessRate = float64(s.stats.AliveHosts) / float64(s.stats.TotalHosts) * 100
	}
}

// outputStats 输出统计信息（精简版）
func (s *AliveScanStrategy) outputStats() {
	// 只输出存活主机列表，不输出冗余统计
	for _, host := range s.stats.AliveHostList {
		common.LogSuccess(fmt.Sprintf("alive %s", host))
	}
}

// PrepareTargets 存活探测不需要准备扫描目标
func (s *AliveScanStrategy) PrepareTargets(info common.HostInfo) []common.HostInfo {
	// 存活探测不需要返回目标列表，因为它不进行后续扫描
	return nil
}

// GetPlugins 存活探测不使用插件
func (s *AliveScanStrategy) GetPlugins(config *common.Config) ([]string, bool) {
	return []string{}, false
}
