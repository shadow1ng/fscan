package main

import (
	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/Core"
	"os"
)

func main() {
	Common.InitLogger()
	defer Common.CloseLogger() // 确保程序退出时关闭日志文件

	var Info Common.HostInfo
	Common.Flag(&Info)
	if err := Common.Parse(&Info); err != nil {
		os.Exit(1) // 直接退出即可，日志已经同步写入
	}
	Core.Scan(Info)
}
