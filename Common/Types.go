// Config/types.go
package Common

type HostInfo struct {
	Host    string
	Ports   string
	Url     string
	Infostr []string
}

// ScanPlugin 定义扫描插件的结构
type ScanPlugin struct {
	Name     string                // 插件名称
	Port     int                   // 关联的端口号，0表示特殊扫描类型
	ScanFunc func(*HostInfo) error // 扫描函数
}

// PluginManager 管理插件注册
var PluginManager = make(map[string]ScanPlugin)

// RegisterPlugin 注册插件
func RegisterPlugin(name string, plugin ScanPlugin) {
	PluginManager[name] = plugin
}
