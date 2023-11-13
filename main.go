package main

import (
	"fmt"
	"github.com/shadow1ng/fscan/Plugins"
	"github.com/shadow1ng/fscan/common"
	"time"
)

func main() {
	start := time.Now()
	var Info common.HostInfo
	common.Flag(&Info)
	common.Parse(&Info)
	Plugins.Scan(Info)
	fmt.Printf("[*] 扫描结束,耗时: %s\n", time.Since(start))
}
