package main

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/Core"
	"os"
	"time"
)

func main() {

	start := time.Now()
	var Info Common.HostInfo
	Common.Flag(&Info)
	if err := Common.Parse(&Info); err != nil {
		os.Exit(1) // 或者其他错误处理
	}
	Core.Scan(Info)
	fmt.Printf("[*] 扫描结束,耗时: %s\n", time.Since(start))
}
