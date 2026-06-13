package core

import (
	"context"
	"math"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
)

// NetworkEnv 网络环境分类
type NetworkEnv int

const (
	EnvLAN      NetworkEnv = iota // 内网: RTT < 5ms, 丢包 < 1%
	EnvWAN                        // 局域网/专线: RTT 5~50ms, 丢包 < 5%
	EnvInternet                   // 公网: RTT 50~200ms
	EnvSlow                       // 慢速/高丢包: RTT > 200ms 或 丢包 > 10%
)

func (e NetworkEnv) String() string {
	switch e {
	case EnvLAN:
		return i18n.GetText("net_env_lan")
	case EnvWAN:
		return i18n.GetText("net_env_wan")
	case EnvInternet:
		return i18n.GetText("net_env_internet")
	default:
		return i18n.GetText("net_env_slow")
	}
}

// NetworkProfile 网络探测结果
type NetworkProfile struct {
	Env       NetworkEnv
	RTTMin    time.Duration
	RTTMedian time.Duration
	RTTP95    time.Duration
	RTTStddev time.Duration
	LossRate  float64
	Samples   int
}

// RecommendConcurrency 根据探测结果推荐并发参数
// 返回 (target, ceiling)
//   - target: 推荐的目标并发数
//   - ceiling: 允许的最大并发数
//
// 如果用户显式指定了 -t，ceiling = 用户值，target 取 min(推荐值, 用户值)
// 如果用户未指定，target 和 ceiling 均为推荐值
func (p *NetworkProfile) RecommendConcurrency(userThreadNum int, explicit bool) (target, ceiling int) {
	// 基于网络环境的缩放因子
	var factor float64
	switch p.Env {
	case EnvLAN:
		factor = 1.5
	case EnvWAN:
		factor = 1.0
	case EnvInternet:
		factor = 0.4
	case EnvSlow:
		factor = 0.15
	}

	recommended := int(float64(userThreadNum) * factor)
	if recommended < 10 {
		recommended = 10
	}

	// 丢包率高时进一步压缩
	if p.LossRate > 0.05 {
		recommended = int(float64(recommended) * (1.0 - p.LossRate))
		if recommended < 10 {
			recommended = 10
		}
	}

	if explicit {
		ceiling = userThreadNum
		target = recommended
		if target > ceiling {
			target = ceiling
		}
	} else {
		target = recommended
		ceiling = recommended
	}
	return
}

// probePorts 探测用的端口列表（高响应率的常见端口）
var probePorts = []int{80, 443, 22, 445, 8080, 3389, 21, 8443}

func networkProbeAddress(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// ProbeNetwork 探测目标网络环境
// 从 hosts 中抽样，用低并发 TCP 连接测量 RTT 和丢包率
// 整个过程控制在数秒内完成
func ProbeNetwork(ctx context.Context, hosts []string, session *common.ScanSession) *NetworkProfile {
	if len(hosts) == 0 {
		return defaultProfile()
	}

	// 抽样：均匀分布，最多 10 个
	samples := pickSamples(hosts, 10)
	probeTimeout := session.Config.Timeout
	if probeTimeout > time.Second {
		probeTimeout = time.Second
	}
	if probeTimeout < 500*time.Millisecond {
		probeTimeout = 500 * time.Millisecond
	}

	var (
		mu       sync.Mutex
		rtts     []time.Duration
		failures int
		total    int
	)

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, host := range samples {
		for _, port := range probePorts {
			select {
			case <-ctx.Done():
				goto done
			default:
			}

			total++
			wg.Add(1)
			sem <- struct{}{}

			go func(h string, p int) {
				defer func() { <-sem; wg.Done() }()

				addr := networkProbeAddress(h, p)
				start := time.Now()
				conn, err := session.DialTCP(ctx, "tcp", addr, probeTimeout)
				rtt := time.Since(start)

				mu.Lock()
				defer mu.Unlock()

				if err != nil {
					// 连接拒绝也是有效的 RTT 样本（说明对端可达）
					if isConnectionRefused(err) {
						rtts = append(rtts, rtt)
					}
					failures++
				} else {
					_ = conn.Close()
					rtts = append(rtts, rtt)
				}
			}(host, port)
		}
	}
done:
	wg.Wait()

	return classifyNetwork(rtts, failures, total)
}

func classifyNetwork(rtts []time.Duration, failures, total int) *NetworkProfile {
	if len(rtts) == 0 {
		return defaultProfile()
	}

	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })

	n := len(rtts)
	median := rtts[n/2]
	p95idx := int(float64(n) * 0.95)
	if p95idx >= n {
		p95idx = n - 1
	}
	p95 := rtts[p95idx]

	// 标准差
	var sum float64
	for _, r := range rtts {
		sum += float64(r)
	}
	mean := sum / float64(n)
	var variance float64
	for _, r := range rtts {
		d := float64(r) - mean
		variance += d * d
	}
	stddev := time.Duration(math.Sqrt(variance / float64(n)))

	// 丢包率：只计算超时的（非 refused），但简化为 1 - 有效响应数/总数
	lossRate := 1.0 - float64(n)/float64(total)
	if lossRate < 0 {
		lossRate = 0
	}

	// 分类
	env := classifyEnv(median, lossRate)

	return &NetworkProfile{
		Env:       env,
		RTTMin:    rtts[0],
		RTTMedian: median,
		RTTP95:    p95,
		RTTStddev: stddev,
		LossRate:  lossRate,
		Samples:   n,
	}
}

func classifyEnv(median time.Duration, lossRate float64) NetworkEnv {
	switch {
	case lossRate > 0.10:
		return EnvSlow
	case median < 5*time.Millisecond && lossRate < 0.01:
		return EnvLAN
	case median < 50*time.Millisecond && lossRate < 0.05:
		return EnvWAN
	case median < 200*time.Millisecond:
		return EnvInternet
	default:
		return EnvSlow
	}
}

func defaultProfile() *NetworkProfile {
	return &NetworkProfile{
		Env:       EnvWAN,
		RTTMedian: 10 * time.Millisecond,
		LossRate:  0,
		Samples:   0,
	}
}

// pickSamples 均匀抽样
func pickSamples(hosts []string, maxSamples int) []string {
	if maxSamples <= 0 {
		return nil
	}
	n := len(hosts)
	if n <= maxSamples {
		return hosts
	}
	step := n / maxSamples
	samples := make([]string, 0, maxSamples)
	for i := 0; i < n && len(samples) < maxSamples; i += step {
		samples = append(samples, hosts[i])
	}
	return samples
}

func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	// connection refused 通常包含 "refused" 关键词
	// 在不同 OS 上表现一致
	return containsFold(err.Error(), "refused")
}

// isTimeoutError 判断是否为超时错误
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return containsFold(err.Error(), "timeout") || containsFold(err.Error(), "deadline")
}
