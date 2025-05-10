package main

import (
	"flag"

	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/Remote/server"
)

func main() {
	// 初始化日志系统
	Common.InitLogger()

	var apiURL string
	var secret string
	var transport string
	var Info Common.HostInfo
	flag.StringVar(&apiURL, "api", "", "RPC调用地址")
	flag.StringVar(&secret, "secret", "", "RPC调用使用的秘钥")
	flag.StringVar(&transport, "transport", "stdio", "MCP传输协议：stdio 或 sse")
	Common.Flag(&Info)
	//模式参数，因为在initoutput中会使用，所以需要在这里设置
	Common.ApiAddr = "remote"
	if apiURL != "" {
		server.StartApiServer(apiURL, secret)
	} else {
		server.StartMcpServer(transport)
	}
}
