package main

import (
	"fmt"
	"os"

	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/Core"
)

func main() {
	Common.InitLogger()

	var Info Common.HostInfo
	Common.Flag(&Info)

	// 解析 CLI 参数
	if err := Common.Parse(&Info); err != nil {
		os.Exit(1)
	}

	// 初始化输出系统，如果失败则直接退出
	if err := Common.InitOutput(); err != nil {
		Common.LogError(fmt.Sprintf("初始化输出系统失败: %v", err))
		os.Exit(1)
	}
	defer Common.CloseOutput()

	// 执行 CLI 扫描逻辑
	Core.Scan(Info)
}
