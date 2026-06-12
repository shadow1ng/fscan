package core

import (
	"fmt"
	"math"
	"runtime"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
)

// EnvironmentProfile 综合环境探测结果
type EnvironmentProfile struct {
	Net    NetworkProfile
	System SystemProfile
}

// SystemProfile 系统能力信息
type SystemProfile struct {
	FDLimit int // 文件描述符上限（0 表示未知）
	NumCPU  int
}

// ProbeSystem 探测系统能力（不需要网络目标）
func ProbeSystem() SystemProfile {
	p := SystemProfile{
		NumCPU: runtime.NumCPU(),
	}
	p.FDLimit = getFDLimit()
	return p
}

// TuneConfig 根据探测结果调整 Config 中的参数
// 只调整用户未显式指定的参数
// 每个参数的推导都有明确的公式和探测依据
func (ep *EnvironmentProfile) TuneConfig(config *common.Config, session *common.ScanSession) {
	net := &ep.Net
	sys := &ep.System

	// ---------- ThreadNum ----------
	// 已在 AdaptivePool 层处理（ProbeNetwork + AIMD），这里不重复

	// ---------- Timeout ----------
	// 公式: median_rtt + 4 * stddev，下限 1s，上限 10s
	// 依据: 与 AdaptiveTimeout 相同的统计原理（覆盖 99.9% 的正常连接）
	if !isExplicit(config, "time") && net.Samples > 0 {
		computed := net.RTTMedian + 4*net.RTTStddev
		// 下限：连接建立至少需要 2 个 RTT（SYN + SYN-ACK）+ 处理时间
		minTO := net.RTTMedian*3 + 200*time.Millisecond
		if computed < minTO {
			computed = minTO
		}
		computed = clampDuration(computed, time.Second, 10*time.Second)

		old := config.Timeout
		config.Timeout = computed
		session.LogDebug(fmt.Sprintf("Timeout: %v -> %v (RTT median=%v stddev=%v)",
			old, computed, net.RTTMedian, net.RTTStddev))
	}

	// ---------- ModuleThreadNum ----------
	// 公式: ThreadNum / 30，下限 5，上限 50
	// 依据: 插件级并发（爆破等）不应超过端口扫描并发的 ~3%
	//       单个服务的连接能力远低于 TCP SYN 扫描
	//       公网服务通常有限流（MaxStartups 等），并发过高适得其反
	if !isExplicit(config, "mt") {
		target, _ := net.RecommendConcurrency(config.ThreadNum, config.ThreadNumExplicit)
		computed := target / 30
		computed = clampInt(computed, 5, 50)

		// 高丢包环境进一步压低，避免大量连接被丢弃浪费
		if net.LossRate > 0.1 {
			computed = computed * 2 / 3
			if computed < 5 {
				computed = 5
			}
		}

		old := config.ModuleThreadNum
		config.ModuleThreadNum = computed
		session.LogDebug(fmt.Sprintf("ModuleThreadNum: %d -> %d (target_concurrency=%d)", old, computed, target))
	}

	// ---------- MaxRetries ----------
	// 公式: ceil(log(0.01) / log(loss_rate))
	// 含义: 重试 N 次后仍然全部丢包的概率 < 1%
	// 例: 丢包率 5% → N=2, 丢包率 20% → N=3, 丢包率 50% → N=7
	// 下限 1（零丢包也至少试一次），上限 6（避免对不可达目标死磕）
	if !isExplicit(config, "retry") && net.Samples > 0 {
		computed := computeRetries(net.LossRate)
		old := config.MaxRetries
		config.MaxRetries = computed
		session.LogDebug(fmt.Sprintf("MaxRetries: %d -> %d (loss_rate=%.2f%%)", old, computed, net.LossRate*100))
	}

	// ---------- ICMPRate ----------
	// 公式: 基于 fd limit 和网络环境
	// 内网 fd 充裕: 0.5（高速发包）
	// 公网或 fd 紧张: 0.1（默认保守）
	// 依据: ICMP 发包速率受两个约束：网络带宽和本机 fd/socket 资源
	if !isExplicit(config, "icmp-rate") && net.Samples > 0 {
		computed := computeICMPRate(net, sys)
		old := config.Network.ICMPRate
		config.Network.ICMPRate = computed
		session.LogDebug(fmt.Sprintf("ICMPRate: %.2f -> %.2f (env=%s fd=%d)", old, computed, net.Env, sys.FDLimit))
	}

	// ---------- PocNum ----------
	// 公式: 与 ModuleThreadNum 一致
	// 依据: POC 检测和凭据爆破的并发约束相同——都是对目标服务发起连接
	if !isExplicit(config, "num") {
		old := config.POC.Num
		config.POC.Num = config.ModuleThreadNum
		session.LogDebug(fmt.Sprintf("PocNum: %d -> %d (follows ModuleThreadNum)", old, config.POC.Num))
	}

	// ---------- DisablePing ----------
	// 由 probeWithICMP 自动处理（尝试 → 失败 → 降级），无需在此干预

	// 总结日志
	if net.Samples > 0 {
		session.LogInfo(i18n.Tr("env_tune_summary",
			config.Timeout.Milliseconds(),
			config.ModuleThreadNum,
			config.MaxRetries,
			fmt.Sprintf("%.2f", config.Network.ICMPRate),
			config.POC.Num))
	}

	// fd limit 约束：总并发不应超过 fd limit 的 60%（留余量给系统）
	if sys.FDLimit > 0 {
		maxConcurrency := sys.FDLimit * 6 / 10
		if config.ThreadNum > maxConcurrency {
			session.LogInfo(i18n.Tr("env_fd_limit", config.ThreadNum, maxConcurrency, sys.FDLimit))
			config.ThreadNum = maxConcurrency
		}
	}
}

// computeRetries 基于丢包率计算重试次数
// 目标：重试 N 次后仍全部失败的概率 < 1%
func computeRetries(lossRate float64) int {
	if lossRate <= 0.001 {
		return 1 // 几乎无丢包
	}
	if lossRate >= 0.95 {
		return 6 // 上限
	}
	// P(N次全失败) = lossRate^N < 0.01
	// N > log(0.01) / log(lossRate)
	n := math.Ceil(math.Log(0.01) / math.Log(lossRate))
	return clampInt(int(n), 1, 6)
}

// computeICMPRate 基于环境计算 ICMP 发包速率
func computeICMPRate(net *NetworkProfile, sys *SystemProfile) float64 {
	// 基准：根据 RTT 估算网络可承受的速率
	// RTT 越低，网络越快，可以发更快
	var base float64
	switch net.Env {
	case EnvLAN:
		base = 0.5
	case EnvWAN:
		base = 0.3
	case EnvInternet:
		base = 0.1
	default:
		base = 0.05
	}

	// fd 约束：fd limit 低时压低速率
	if sys.FDLimit > 0 && sys.FDLimit < 1024 {
		base = base * float64(sys.FDLimit) / 1024.0
		if base < 0.02 {
			base = 0.02
		}
	}

	return base
}

// isExplicit 检查参数是否被用户显式指定
// 目前只有 ThreadNum 有 explicit 标记，其他参数通过检查是否为默认值来判断
func isExplicit(config *common.Config, flagName string) bool {
	switch flagName {
	case "t":
		return config.ThreadNumExplicit
	case "time":
		return config.Timeout != 3*time.Second // 默认值
	case "mt":
		return config.ModuleThreadNum != 20 // 默认值
	case "retry":
		return config.MaxRetries != 3 // 默认值
	case "icmp-rate":
		return config.Network.ICMPRate != 0.1 // 默认值
	case "num":
		return config.POC.Num != 20 // 默认值
	}
	return false
}

func clampInt(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func clampDuration(v, min, max time.Duration) time.Duration {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
