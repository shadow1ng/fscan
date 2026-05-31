package core

import (
	"fmt"
	"sync"
	"testing"
)

/*
socket_iterator_test.go - SocketIterator 高价值测试

测试重点：
1. 端口喷洒顺序 - 这是核心设计，顺序错误会导致单IP限速
2. 并发安全性 - 多worker并发调用Next()不丢失不重复
3. 边界情况 - 空输入、单元素

不测试：
- getter方法（Total）- 太简单
- 内部状态 - 只关心外部行为
*/

// TestSocketIterator_PortSprayOrder 验证端口喷洒顺序
//
// 这是最重要的测试：顺序必须是先遍历所有IP的同一端口，再换端口
// 正确顺序：Port1[IP1,IP2,IP3] → Port2[IP1,IP2,IP3]
// 错误顺序：IP1[Port1,Port2,Port3] → IP2[Port1,Port2,Port3]
func TestSocketIterator_PortSprayOrder(t *testing.T) {
	hosts := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}
	ports := []int{80, 443}

	it := NewSocketIterator(hosts, ports, nil)

	// 期望的顺序：先所有IP的80端口，再所有IP的443端口
	expected := []struct {
		host string
		port int
	}{
		{"192.168.1.1", 80},
		{"192.168.1.2", 80},
		{"192.168.1.3", 80},
		{"192.168.1.1", 443},
		{"192.168.1.2", 443},
		{"192.168.1.3", 443},
	}

	for i, exp := range expected {
		host, port, ok := it.Next()
		if !ok {
			t.Fatalf("第%d次迭代提前结束", i+1)
		}
		if host != exp.host || port != exp.port {
			t.Errorf("第%d次迭代: 期望 %s:%d, 实际 %s:%d",
				i+1, exp.host, exp.port, host, port)
		}
	}

	// 验证迭代结束
	_, _, ok := it.Next()
	if ok {
		t.Error("迭代应该已结束")
	}
}

// TestSocketIterator_ConcurrentSafety 验证并发安全性
//
// 多个goroutine同时调用Next()，所有任务必须：
// 1. 不丢失 - 每个host:port组合只出现一次
// 2. 不重复 - 总数等于预期
func TestSocketIterator_ConcurrentSafety(t *testing.T) {
	// 构造较大的测试集
	hosts := make([]string, 100)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("192.168.1.%d", i+1)
	}
	ports := []int{22, 80, 443, 3306, 6379}

	it := NewSocketIterator(hosts, ports, nil)
	expectedTotal := len(hosts) * len(ports)

	// 记录所有结果
	results := make(map[string]int)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 启动10个并发worker
	workers := 10
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				host, port, ok := it.Next()
				if !ok {
					return
				}
				key := fmt.Sprintf("%s:%d", host, port)
				mu.Lock()
				results[key]++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// 验证：每个组合只出现一次
	if len(results) != expectedTotal {
		t.Errorf("任务丢失或重复: 期望 %d 个唯一组合, 实际 %d", expectedTotal, len(results))
	}

	// 验证：没有重复
	for key, count := range results {
		if count != 1 {
			t.Errorf("任务重复: %s 出现 %d 次", key, count)
		}
	}
}

// TestSocketIterator_ExcludePorts 验证端口过滤
func TestSocketIterator_ExcludePorts(t *testing.T) {
	hosts := []string{"192.168.1.1"}
	ports := []int{22, 80, 443, 3306}
	exclude := map[int]struct{}{
		80:   {},
		3306: {},
	}

	it := NewSocketIterator(hosts, ports, exclude)

	// 应该只有22和443，按优先级排序：443(优先级2) 在 22(优先级3) 之前
	var gotPorts []int
	for {
		_, port, ok := it.Next()
		if !ok {
			break
		}
		gotPorts = append(gotPorts, port)
	}

	if len(gotPorts) != 2 {
		t.Fatalf("期望2个端口, 实际 %d", len(gotPorts))
	}
	// 443优先级高于22，所以443在前
	if gotPorts[0] != 443 || gotPorts[1] != 22 {
		t.Errorf("期望 [443, 22] (按优先级排序), 实际 %v", gotPorts)
	}

	// 验证Total也正确
	if it.Total() != 2 {
		t.Errorf("Total() 应该是2, 实际 %d", it.Total())
	}
}

// TestSocketIterator_EmptyInputs 验证边界情况
func TestSocketIterator_EmptyInputs(t *testing.T) {
	t.Run("空hosts", func(t *testing.T) {
		it := NewSocketIterator(nil, []int{80}, nil)
		_, _, ok := it.Next()
		if ok {
			t.Error("空hosts应该立即返回false")
		}
		if it.Total() != 0 {
			t.Errorf("Total() 应该是0, 实际 %d", it.Total())
		}
	})

	t.Run("空ports", func(t *testing.T) {
		it := NewSocketIterator([]string{"192.168.1.1"}, nil, nil)
		_, _, ok := it.Next()
		if ok {
			t.Error("空ports应该立即返回false")
		}
	})

	t.Run("全部被排除", func(t *testing.T) {
		exclude := map[int]struct{}{80: {}, 443: {}}
		it := NewSocketIterator([]string{"192.168.1.1"}, []int{80, 443}, exclude)
		_, _, ok := it.Next()
		if ok {
			t.Error("全部端口被排除应该立即返回false")
		}
	})
}

func TestSocketIteratorTotalUsesInt64(t *testing.T) {
	hosts := make([]string, 1<<20)
	ports := make([]int, 4096)
	it := NewSocketIterator(hosts, ports, nil)

	want := int64(len(hosts)) * int64(len(ports))
	if it.Total() != want {
		t.Fatalf("Total() = %d, want %d", it.Total(), want)
	}
}

// TestSocketIterator_PortPrioritySort 验证端口优先级排序
// 高价值端口（80, 443, 22等）应该排在前面
func TestSocketIterator_PortPrioritySort(t *testing.T) {
	hosts := []string{"192.168.1.1"}
	// 故意乱序输入，包含高优先级和普通端口
	ports := []int{9999, 22, 8888, 80, 7777, 443, 3389, 1234}

	it := NewSocketIterator(hosts, ports, nil)

	var gotPorts []int
	for {
		_, port, ok := it.Next()
		if !ok {
			break
		}
		gotPorts = append(gotPorts, port)
	}

	// 期望顺序：高优先级端口按优先级排序，然后是普通端口按数字升序
	// 80(优先级1), 443(2), 22(3), 3389(4), 然后 1234, 7777, 8888, 9999
	expected := []int{80, 443, 22, 3389, 1234, 7777, 8888, 9999}

	if len(gotPorts) != len(expected) {
		t.Fatalf("端口数量不匹配: 期望 %d, 实际 %d", len(expected), len(gotPorts))
	}

	for i, exp := range expected {
		if gotPorts[i] != exp {
			t.Errorf("第%d个端口: 期望 %d, 实际 %d\n完整结果: %v", i, exp, gotPorts[i], gotPorts)
			break
		}
	}
}

// TestSocketIterator_SingleElements 验证单元素情况
func TestSocketIterator_SingleElements(t *testing.T) {
	t.Run("单IP单端口", func(t *testing.T) {
		it := NewSocketIterator([]string{"10.0.0.1"}, []int{8080}, nil)

		host, port, ok := it.Next()
		if !ok || host != "10.0.0.1" || port != 8080 {
			t.Errorf("期望 10.0.0.1:8080, 实际 %s:%d, ok=%v", host, port, ok)
		}

		_, _, ok = it.Next()
		if ok {
			t.Error("应该只有一个元素")
		}
	})
}
