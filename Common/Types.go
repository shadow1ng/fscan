// Config/types.go
package Common

type HostInfo struct {
	Host    string
	Ports   string
	Url     string
	Infostr []string
}

// 在 Common/const.go 中添加
// 插件类型常量
const (
	PluginTypeService = "service" // 服务类型插件
	PluginTypeWeb     = "web"     // Web类型插件
	PluginTypeLocal   = "local"   // 本地类型插件
)

// ScanPlugin 定义扫描插件的结构
type ScanPlugin struct {
	Name     string                // 插件名称
	Ports    []int                 // 适用端口
	Types    []string              // 插件类型标签，一个插件可以有多个类型
	ScanFunc func(*HostInfo) error // 扫描函数
}

// 添加一个用于检查插件类型的辅助方法
func (p ScanPlugin) HasType(typeName string) bool {
	for _, t := range p.Types {
		if t == typeName {
			return true
		}
	}
	return false
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
