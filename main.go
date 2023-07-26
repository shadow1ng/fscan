package main

import (
	"fmt"
	"time"

	"github.com/shadow1ng/fscan/Plugins"
	"github.com/shadow1ng/fscan/common"
)

func main() {
	start := time.Now()
	var config common.InConfig
	common.Flag(&config)
	common.Parse(&config)
	Plugins.Scan(config.HostInfo, config.Flags)
	t := time.Now().Sub(start)
	fmt.Printf("[*] 扫描结束,耗时: %s\n", t)
}
