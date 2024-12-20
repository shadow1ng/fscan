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
	Ports    []int                 // 关联的端口列表，空切片表示特殊扫描类型
	ScanFunc func(*HostInfo) error // 扫描函数
}

// HasPort 检查插件是否支持指定端口
func (p *ScanPlugin) HasPort(port int) bool {
	// 如果没有指定端口列表，表示支持所有端口
	if len(p.Ports) == 0 {
		return true
	}

	// 检查端口是否在支持列表中
	for _, supportedPort := range p.Ports {
		if port == supportedPort {
			return true
		}
	}
	return false
}

// PluginManager 管理插件注册
var PluginManager = make(map[string]ScanPlugin)

// RegisterPlugin 注册插件
func RegisterPlugin(name string, plugin ScanPlugin) {
	PluginManager[name] = plugin
}
