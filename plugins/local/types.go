package local

import (
	"context"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/plugins"
)

// Plugin 本地插件接口 - 不需要端口概念
type Plugin interface {
	Name() string
	Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result
}

// RegisterLocalPlugin 注册本地插件 - 自动标记local类型
func RegisterLocalPlugin(name string, creator func() Plugin) {
	plugins.RegisterWithTypes(name, func() plugins.Plugin {
		return creator()
	}, []int{}, []string{plugins.PluginTypeLocal})
}
