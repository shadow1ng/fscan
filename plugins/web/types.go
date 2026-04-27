package web

import (
	"context"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/plugins"
)

// WebPlugin Web插件接口 - 使用智能HTTP检测，不需要预定义端口
type WebPlugin interface {
	Name() string
	Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *WebScanResult
}

// WebScanResult Web扫描结果类型别名
type WebScanResult = plugins.Result

// RegisterWebPlugin 注册Web插件 - 自动标记web类型
func RegisterWebPlugin(name string, creator func() WebPlugin) {
	plugins.RegisterWithTypes(name, func() plugins.Plugin {
		return creator()
	}, []int{}, []string{plugins.PluginTypeWeb})
}
