package services

import (
	"context"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/plugins"
)

// 插件接口定义 - 统一命名风格
type Plugin interface {
	Name() string
	Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult
}

type ScanResult = plugins.Result
type ExploitResult = plugins.ExploitResult
type Exploiter = plugins.Exploiter
type Credential = plugins.Credential

// RegisterPluginWithPorts 高效注册：直接传递端口信息，避免实例创建
func RegisterPluginWithPorts(name string, factory func() Plugin, ports []int) {
	plugins.RegisterWithPorts(name, func() plugins.Plugin {
		return factory()
	}, ports)
}

var GenerateCredentials = plugins.GenerateCredentials
