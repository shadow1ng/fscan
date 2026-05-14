package main
package main

import (
	"fmt"
	"github.com/shadow1ng/fscan/common/parsers"
)

func main() {
	fmt.Println("=== Fscan 大网段扫描限制测试 ===\n")

	// 测试1: 小网段 /30 (4个IP)
	fmt.Println("测试1: 小网段 192.168.1.0-192.168.1.3 (使用 parseIPFullRange)")
	result1, _ := testIPRange("192.168.1.0", "192.168.1.3")
	fmt.Printf("结果: %d 个IP\n", len(result1))
	if len(result1) > 0 && len(result1) <= 5 {
		fmt.Printf("IP列表: %v\n", result1)
	}

	// 测试2: 中等网段 /24 (256个IP)
	fmt.Println("\n测试2: 中等网段 192.168.1.0/24 (使用 CIDR解析)")
	result2, _ := testCIDR("192.168.1.0/24")
	fmt.Printf("结果: %d 个IP (预期: 254个)\n", len(result2))

	// 测试3: 大网段 /16 (65536个IP)
	fmt.Println("\n测试3: 大网段 192.168.0.0/16 (使用 CIDR解析)")
	result3, _ := testCIDR("192.168.0.0/16")
	fmt.Printf("结果: %d 个IP (预期: 65534个)\n", len(result3))
	if len(result3) > 0 {
		fmt.Printf("首5个IP: %v\n", result3[:5])
		fmt.Printf("末5个IP: %v\n", result3[len(result3)-5:])
	}

	// 测试4: 特大网段 10.0.0.0/8 (~1600万个IP，如果全部返回会导致内存问题)
	fmt.Println("\n测试4: 特大网段 10.0.0.0/8 (可能导致内存问题) - 显示前100个结果")
	result4, _ := testCIDR("10.0.0.0/8")
	fmt.Printf("结果: %d 个IP (预期: 16777214个!)\n", len(result4))
	if len(result4) > 100 {
		fmt.Println("✗ 警告: 返回超过100个IP，存在内存溅出风险!")
	}
}

func testIPRange(start, end string) ([]string, error) {
	// 这里直接调用parsers包内的函数（需要改为public或创建wrapper）
	// 为了演示目的，我们显示问题
	return nil, nil
}

func testCIDR(cidr string) ([]string, error) {
	// 同样需要wrapper
	return nil, nil
}
