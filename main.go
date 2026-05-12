package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/debug"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/core"
	"github.com/shadow1ng/fscan/web"

	// 导入统一插件系统
	_ "github.com/shadow1ng/fscan/plugins/local"
	_ "github.com/shadow1ng/fscan/plugins/services"
	_ "github.com/shadow1ng/fscan/plugins/web"
)

func main() {
	// 启动 pprof（仅调试版本）
	debug.Start()
	defer debug.Stop()

	// 解析命令行参数
	var info common.HostInfo
	if err := common.Flag(&info); err != nil {
		if err == common.ErrShowHelp {
			os.Exit(0) // 显示帮助是正常退出
		}
		common.LogError(i18n.Tr("param_error", err))
		os.Exit(1)
	}

	// Web模式：启动Web服务器
	if common.WebMode {
		if err := web.StartServer(common.WebPort); err != nil {
			common.LogError(err.Error())
			os.Exit(1)
		}
		return
	}

	// 检查参数互斥性
	if err := common.ValidateExclusiveParams(&info); err != nil {
		common.LogError(i18n.Tr("error_generic", err))
		os.Exit(1)
	}

	// 统一初始化：解析 → 配置 → 输出
	result, err := common.Initialize(&info)
	if err != nil {
		common.LogError(i18n.Tr("init_failed", err))
		os.Exit(1)
	}

	// 设置信号处理，确保 Ctrl+C 时能正确保存结果
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		common.LogInfo(i18n.GetText("received_exit_signal"))
		_ = common.Cleanup() // 确保结果写入磁盘
		os.Exit(130)         // 128 + SIGINT(2) = 130，标准的中断退出码
	}()
	defer func() { _ = common.Cleanup() }()
	defer common.CloseLogger()

	// 执行扫描
	core.RunScan(context.Background(), *result.Info, result.Session)
}
