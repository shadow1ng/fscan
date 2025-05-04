package Core

import (
	"context"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// EnhancedPortScan 高性能端口扫描函数
func EnhancedPortScan(hosts []string, ports string, timeout int64) []string {
	// 解析端口和排除端口
	portList := Common.ParsePort(ports)
	if len(portList) == 0 {
		Common.LogError("无效端口: " + ports)
		return nil
	}

	exclude := make(map[int]struct{})
	for _, p := range Common.ParsePort(Common.ExcludePorts) {
		exclude[p] = struct{}{}
	}

	// 初始化并发控制
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	to := time.Duration(timeout) * time.Second
	sem := semaphore.NewWeighted(int64(Common.ThreadNum))
	var count int64
	var aliveMap sync.Map
	g, ctx := errgroup.WithContext(ctx)

	// 并发扫描所有目标
	for _, host := range hosts {
		for _, port := range portList {
			if _, excluded := exclude[port]; excluded {
				continue
			}

			host, port := host, port // 捕获循环变量
			addr := fmt.Sprintf("%s:%d", host, port)

			if err := sem.Acquire(ctx, 1); err != nil {
				break
			}

			g.Go(func() error {
				defer sem.Release(1)

				// 连接测试
				conn, err := net.DialTimeout("tcp", addr, to)
				if err != nil {
					return nil
				}
				defer conn.Close()

				// 记录开放端口
				atomic.AddInt64(&count, 1)
				aliveMap.Store(addr, struct{}{})
				Common.LogSuccess("端口开放 " + addr)
				Common.SaveResult(&Common.ScanResult{
					Time: time.Now(), Type: Common.PORT, Target: host,
					Status: "open", Details: map[string]interface{}{"port": port},
				})

				// 服务识别
				if Common.EnableFingerprint {
					if info, err := NewPortInfoScanner(host, port, conn, to).Identify(); err == nil {
						// 构建结果详情
						details := map[string]interface{}{"port": port, "service": info.Name}
						if info.Version != "" {
							details["version"] = info.Version
						}

						// 处理额外信息
						for k, v := range info.Extras {
							if v == "" {
								continue
							}
							switch k {
							case "vendor_product":
								details["product"] = v
							case "os", "info":
								details[k] = v
							}
						}
						if len(info.Banner) > 0 {
							details["banner"] = strings.TrimSpace(info.Banner)
						}

						// 保存服务结果
						Common.SaveResult(&Common.ScanResult{
							Time: time.Now(), Type: Common.SERVICE, Target: host,
							Status: "identified", Details: details,
						})

						// 记录服务信息
						var sb strings.Builder
						sb.WriteString("服务识别 " + addr + " => ")
						if info.Name != "unknown" {
							sb.WriteString("[" + info.Name + "]")
						}
						if info.Version != "" {
							sb.WriteString(" 版本:" + info.Version)
						}

						for k, v := range info.Extras {
							if v == "" {
								continue
							}
							switch k {
							case "vendor_product":
								sb.WriteString(" 产品:" + v)
							case "os":
								sb.WriteString(" 系统:" + v)
							case "info":
								sb.WriteString(" 信息:" + v)
							}
						}

						if len(info.Banner) > 0 && len(info.Banner) < 100 {
							sb.WriteString(" Banner:[" + strings.TrimSpace(info.Banner) + "]")
						}

						Common.LogSuccess(sb.String())
					}
				}

				return nil
			})
		}
	}

	_ = g.Wait()

	// 收集结果
	var aliveAddrs []string
	aliveMap.Range(func(key, _ interface{}) bool {
		aliveAddrs = append(aliveAddrs, key.(string))
		return true
	})

	Common.LogSuccess(fmt.Sprintf("扫描完成, 发现 %d 个开放端口", count))
	return aliveAddrs
}
