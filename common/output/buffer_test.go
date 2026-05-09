package output

import (
	"fmt"
	"sync"
	"testing"
)

/*
buffer_test.go - ResultBuffer 高价值测试

测试重点：
1. 去重逻辑 - 不同结果类型的去重策略差异
2. 完整度评分 - 决定是否替换已有服务记录
3. 并发安全 - 多goroutine同时Add
*/

// =============================================================================
// 基本去重测试
// =============================================================================

// TestResultBuffer_HostDeduplication 测试主机去重
func TestResultBuffer_HostDeduplication(t *testing.T) {
	buf := NewResultBuffer()

	// 添加相同主机多次
	for i := 0; i < 10; i++ {
		buf.Add(&ScanResult{
			Type:   TypeHost,
			Target: "192.168.1.1",
			Status: "alive",
		})
	}

	hosts, _, _, _ := buf.Summary()
	if hosts != 1 {
		t.Errorf("主机应去重为1个，实际 %d", hosts)
	}
}

// TestResultBuffer_PortDeduplication 测试端口去重
func TestResultBuffer_PortDeduplication(t *testing.T) {
	buf := NewResultBuffer()

	// 相同IP:Port应去重
	for i := 0; i < 5; i++ {
		buf.Add(&ScanResult{
			Type:    TypePort,
			Target:  "192.168.1.1",
			Details: map[string]interface{}{"port": 80},
		})
	}

	// 不同端口不去重
	buf.Add(&ScanResult{
		Type:    TypePort,
		Target:  "192.168.1.1",
		Details: map[string]interface{}{"port": 443},
	})

	_, ports, _, _ := buf.Summary()
	if ports != 2 {
		t.Errorf("端口应有2个（80和443），实际 %d", ports)
	}
}

// TestResultBuffer_ServiceDeduplication 测试服务去重
func TestResultBuffer_ServiceDeduplication(t *testing.T) {
	buf := NewResultBuffer()

	// 相同Target的服务应去重
	buf.Add(&ScanResult{
		Type:   TypeService,
		Target: "192.168.1.1:80",
		Status: "http",
	})
	buf.Add(&ScanResult{
		Type:   TypeService,
		Target: "192.168.1.1:80",
		Status: "nginx",
	})

	_, _, services, _ := buf.Summary()
	if services != 1 {
		t.Errorf("相同Target的服务应去重为1个，实际 %d", services)
	}
}

// TestResultBuffer_VulnDeduplication 测试漏洞去重
func TestResultBuffer_VulnDeduplication(t *testing.T) {
	buf := NewResultBuffer()

	// 相同Target+Status的漏洞应去重
	for i := 0; i < 3; i++ {
		buf.Add(&ScanResult{
			Type:   TypeVuln,
			Target: "192.168.1.1:445",
			Status: "MS17-010",
		})
	}

	// 不同漏洞不去重
	buf.Add(&ScanResult{
		Type:   TypeVuln,
		Target: "192.168.1.1:445",
		Status: "CVE-2020-0796",
	})

	_, _, _, vulns := buf.Summary()
	if vulns != 2 {
		t.Errorf("漏洞应有2个，实际 %d", vulns)
	}
}

// =============================================================================
// 完整度评分测试
// =============================================================================

// TestResultBuffer_CompletenessScore 测试完整度评分
func TestResultBuffer_CompletenessScore(t *testing.T) {
	buf := NewResultBuffer()

	tests := []struct {
		name          string
		result        *ScanResult
		expectedScore int
	}{
		{
			name:          "空Details",
			result:        &ScanResult{Details: nil},
			expectedScore: 0,
		},
		{
			name:          "只有status",
			result:        &ScanResult{Details: map[string]interface{}{"status": 200}},
			expectedScore: 2,
		},
		{
			name:          "有server",
			result:        &ScanResult{Details: map[string]interface{}{"server": "nginx/1.18.0"}},
			expectedScore: 2,
		},
		{
			name:          "有title",
			result:        &ScanResult{Details: map[string]interface{}{"title": "Welcome"}},
			expectedScore: 1,
		},
		{
			name:          "有指纹-[]string",
			result:        &ScanResult{Details: map[string]interface{}{"fingerprints": []string{"nginx"}}},
			expectedScore: 3,
		},
		{
			name:          "有指纹-[]interface{}",
			result:        &ScanResult{Details: map[string]interface{}{"fingerprints": []interface{}{"apache", "php"}}},
			expectedScore: 3,
		},
		{
			name:          "有banner",
			result:        &ScanResult{Details: map[string]interface{}{"banner": "SSH-2.0-OpenSSH"}},
			expectedScore: 1,
		},
		{
			name: "完整记录",
			result: &ScanResult{
				Details: map[string]interface{}{
					"status":       200,
					"server":       "nginx",
					"title":        "Home",
					"fingerprints": []string{"nginx", "php"},
					"banner":       "test",
				},
			},
			expectedScore: 9, // 2+2+1+3+1
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := buf.CalculateCompleteness(tt.result)
			if score != tt.expectedScore {
				t.Errorf("完整度评分 = %d, 期望 %d", score, tt.expectedScore)
			}
		})
	}
}

// TestResultBuffer_ServiceUpdate 测试服务记录更新
//
// 当新记录比旧记录更完整时，应该替换
func TestResultBuffer_ServiceUpdate(t *testing.T) {
	buf := NewResultBuffer()

	// 先添加简单记录
	buf.Add(&ScanResult{
		Type:    TypeService,
		Target:  "192.168.1.1:80",
		Status:  "http",
		Details: map[string]interface{}{},
	})

	// 再添加更完整的记录
	buf.Add(&ScanResult{
		Type:   TypeService,
		Target: "192.168.1.1:80",
		Status: "http",
		Details: map[string]interface{}{
			"status":       200,
			"server":       "nginx/1.18.0",
			"title":        "Welcome",
			"fingerprints": []string{"nginx", "php"},
		},
	})

	_, _, services, _ := buf.Summary()
	if services != 1 {
		t.Fatal("服务数量应为1")
	}

	// 验证是更完整的记录
	if buf.ServiceResults[0].Details == nil {
		t.Fatal("Details不应为nil")
	}
	if buf.ServiceResults[0].Details["server"] != "nginx/1.18.0" {
		t.Error("应保留更完整的记录")
	}
}

func TestResultBuffer_ServiceUpdateMergesDetails(t *testing.T) {
	buf := NewResultBuffer()

	buf.Add(&ScanResult{
		Type:   TypeService,
		Target: "192.168.1.1:80",
		Status: "identified",
		Details: map[string]interface{}{
			"service": "http",
			"banner":  "HTTP/1.1 200 OK",
		},
	})
	buf.Add(&ScanResult{
		Type:   TypeService,
		Target: "192.168.1.1:80",
		Status: "web",
		Details: map[string]interface{}{
			"title":  "Home",
			"status": 200,
			"server": "nginx",
		},
	})

	if len(buf.ServiceResults) != 1 {
		t.Fatalf("期望1条服务记录，实际 %d", len(buf.ServiceResults))
	}
	details := buf.ServiceResults[0].Details
	for _, key := range []string{"service", "banner", "title", "status", "server"} {
		if _, ok := details[key]; !ok {
			t.Errorf("合并后的服务记录缺少字段 %q: %#v", key, details)
		}
	}
}

// TestResultBuffer_ServiceNoDowngrade 测试不降级服务记录
//
// 当新记录不如旧记录完整时，不应替换
func TestResultBuffer_ServiceNoDowngrade(t *testing.T) {
	buf := NewResultBuffer()

	// 先添加完整记录
	buf.Add(&ScanResult{
		Type:   TypeService,
		Target: "192.168.1.1:80",
		Status: "http",
		Details: map[string]interface{}{
			"status":       200,
			"server":       "nginx/1.18.0",
			"fingerprints": []string{"nginx"},
		},
	})

	// 再添加简单记录
	buf.Add(&ScanResult{
		Type:    TypeService,
		Target:  "192.168.1.1:80",
		Status:  "http",
		Details: map[string]interface{}{},
	})

	// 验证仍保留完整记录
	if buf.ServiceResults[0].Details["server"] != "nginx/1.18.0" {
		t.Error("不应降级到不完整的记录")
	}
}

// =============================================================================
// 并发安全测试
// =============================================================================

// TestResultBuffer_ConcurrentAdd 测试并发添加
func TestResultBuffer_ConcurrentAdd(t *testing.T) {
	buf := NewResultBuffer()

	const goroutines = 100
	const resultsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < resultsPerGoroutine; j++ {
				// 每个goroutine添加不同类型的结果
				switch j % 4 {
				case 0:
					buf.Add(&ScanResult{
						Type:   TypeHost,
						Target: fmt.Sprintf("192.168.%d.%d", id, j),
					})
				case 1:
					buf.Add(&ScanResult{
						Type:    TypePort,
						Target:  fmt.Sprintf("192.168.%d.%d", id, j),
						Details: map[string]interface{}{"port": j},
					})
				case 2:
					buf.Add(&ScanResult{
						Type:   TypeService,
						Target: fmt.Sprintf("192.168.%d.%d:%d", id, j, j),
					})
				case 3:
					buf.Add(&ScanResult{
						Type:   TypeVuln,
						Target: fmt.Sprintf("192.168.%d.%d", id, j),
						Status: fmt.Sprintf("CVE-%d", j),
					})
				}
			}
		}(i)
	}

	wg.Wait()

	// 验证没有panic，数据完整
	hosts, ports, services, vulns := buf.Summary()
	total := hosts + ports + services + vulns

	if total == 0 {
		t.Error("并发添加后应有结果")
	}

	t.Logf("并发测试完成: %d hosts, %d ports, %d services, %d vulns",
		hosts, ports, services, vulns)
}

// TestResultBuffer_ConcurrentSummary 测试并发获取摘要
func TestResultBuffer_ConcurrentSummary(t *testing.T) {
	buf := NewResultBuffer()

	// 预填充一些数据
	for i := 0; i < 100; i++ {
		buf.Add(&ScanResult{
			Type:   TypeHost,
			Target: fmt.Sprintf("192.168.1.%d", i),
		})
	}

	var wg sync.WaitGroup
	wg.Add(100)

	for i := 0; i < 100; i++ {
		go func() {
			defer wg.Done()
			// 同时获取摘要和添加
			buf.Summary()
			buf.Add(&ScanResult{
				Type:   TypeHost,
				Target: "10.0.0.1",
			})
		}()
	}

	wg.Wait()
	// 没有panic即为成功
}

// =============================================================================
// 边界情况测试
// =============================================================================

// TestResultBuffer_NilResult 测试nil结果
func TestResultBuffer_NilResult(t *testing.T) {
	buf := NewResultBuffer()
	buf.Add(nil) // 不应panic

	hosts, ports, services, vulns := buf.Summary()
	if hosts+ports+services+vulns != 0 {
		t.Error("添加nil后应无结果")
	}
}

// TestResultBuffer_PortWithoutDetails 测试无Details的端口
func TestResultBuffer_PortWithoutDetails(t *testing.T) {
	buf := NewResultBuffer()

	buf.Add(&ScanResult{
		Type:    TypePort,
		Target:  "192.168.1.1",
		Details: nil,
	})

	_, ports, _, _ := buf.Summary()
	if ports != 1 {
		t.Error("无Details的端口也应被添加")
	}
}

// TestResultBuffer_Clear 测试清空
func TestResultBuffer_Clear(t *testing.T) {
	buf := NewResultBuffer()

	// 添加各类结果
	buf.Add(&ScanResult{Type: TypeHost, Target: "192.168.1.1"})
	buf.Add(&ScanResult{Type: TypePort, Target: "192.168.1.1", Details: map[string]interface{}{"port": 80}})
	buf.Add(&ScanResult{Type: TypeService, Target: "192.168.1.1:80"})
	buf.Add(&ScanResult{Type: TypeVuln, Target: "192.168.1.1", Status: "CVE-2021-1234"})

	// 清空
	buf.Clear()

	hosts, ports, services, vulns := buf.Summary()
	if hosts+ports+services+vulns != 0 {
		t.Error("Clear后应无结果")
	}

	// 验证可以继续添加
	buf.Add(&ScanResult{Type: TypeHost, Target: "10.0.0.1"})
	hosts, _, _, _ = buf.Summary()
	if hosts != 1 {
		t.Error("Clear后应能继续添加")
	}
}

// TestResultBuffer_EmptyFingerprints 测试空指纹数组
func TestResultBuffer_EmptyFingerprints(t *testing.T) {
	buf := NewResultBuffer()

	// 空字符串数组
	score1 := buf.CalculateCompleteness(&ScanResult{
		Details: map[string]interface{}{"fingerprints": []string{}},
	})
	if score1 != 0 {
		t.Errorf("空指纹数组不应加分，实际 %d", score1)
	}

	// 空interface数组
	score2 := buf.CalculateCompleteness(&ScanResult{
		Details: map[string]interface{}{"fingerprints": []interface{}{}},
	})
	if score2 != 0 {
		t.Errorf("空interface数组不应加分，实际 %d", score2)
	}
}

// TestResultBuffer_StatusZero 测试status为0
func TestResultBuffer_StatusZero(t *testing.T) {
	buf := NewResultBuffer()

	score := buf.CalculateCompleteness(&ScanResult{
		Details: map[string]interface{}{"status": 0},
	})
	if score != 0 {
		t.Errorf("status为0不应加分，实际 %d", score)
	}
}
