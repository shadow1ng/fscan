package main

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/Core"
	"os"
)

func main() {
	Common.InitLogger()

	var Info Common.HostInfo
	Common.Flag(&Info)
	if err := Common.Parse(&Info); err != nil {
		os.Exit(1)
	}
	// 初始化输出系统，如果失败则直接退出
	if err := Common.InitOutput(); err != nil {
		Common.LogError(fmt.Sprintf("初始化输出系统失败: %v", err))
		os.Exit(1) // 关键修改：初始化失败时直接退出
	}
	defer Common.CloseOutput()
	Core.Scan(Info)
}
