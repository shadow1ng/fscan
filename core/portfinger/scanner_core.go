package portfinger

import (
	_ "embed"
	"strings"
	"sync"
)

// ProbeString 嵌入的nmap服务探测数据
//
//go:embed nmap-service-probes.txt
var ProbeString string

// 全局VScan实例（使用sync.Once确保只初始化一次）
var (
	globalVScan  VScan
	globalNull   *Probe
	globalCommon *Probe
	vscanOnce    sync.Once
)

// Init 初始化VScan对象
func (vs *VScan) Init() {
	vs.parseProbesFromContent(ProbeString)
	vs.parseProbesToMapKName()
	vs.SetusedProbes()
	vs.compileFallbacks() // 编译 fallback 数组
	vs.preDecodeProbeData() // 预解码探针数据
}

// preDecodeProbeData 预解码所有探针的 Data 字段，避免运行时重复解码
func (vs *VScan) preDecodeProbeData() {
	for i := range vs.Probes {
		if vs.Probes[i].Data != "" {
			decoded, err := DecodeData(vs.Probes[i].Data)
			if err == nil {
				vs.Probes[i].DecodedData = decoded
			}
		}
	}
	// 同步到 map
	for i := range vs.Probes {
		vs.ProbesMapKName[vs.Probes[i].Name] = vs.Probes[i]
	}
}

// compileFallbacks 编译所有探测器的 fallback 数组
// 参考 Nmap 的 AllProbes::compileFallbacks() 实现
func (vs *VScan) compileFallbacks() {
	// 获取 NULL 探测器指针
	var nullProbe *Probe
	if np, ok := vs.ProbesMapKName["NULL"]; ok {
		nullProbe = &np
		// NULL 探测器的 fallback 只包含自身
		nullProbe.Fallbacks[0] = nullProbe
		vs.ProbesMapKName["NULL"] = *nullProbe
	}

	// 遍历所有探测器，编译 fallback 数组
	for i := range vs.Probes {
		probe := &vs.Probes[i]
		idx := 0

		// fallbacks[0] = 自身
		probe.Fallbacks[idx] = probe
		idx++

		if probe.Fallback == "" {
			// 无 fallback 指令：TCP 使用 [自身, NULL]，UDP 使用 [自身]
			if probe.Protocol == "tcp" && nullProbe != nil {
				probe.Fallbacks[idx] = nullProbe
			}
		} else {
			// 有 fallback 指令：解析逗号分隔的探测器名称
			fallbackNames := strings.Split(probe.Fallback, ",")
			for _, name := range fallbackNames {
				name = strings.TrimSpace(name)
				if name == "" {
					continue
				}
				if idx >= MaxFallbacks {
					break
				}
				if fbProbe, ok := vs.ProbesMapKName[name]; ok {
					probe.Fallbacks[idx] = &fbProbe
					idx++
				}
			}
			// TCP 探测器在末尾添加 NULL 探测器
			if probe.Protocol == "tcp" && nullProbe != nil && idx < MaxFallbacks {
				probe.Fallbacks[idx] = nullProbe
			}
		}
	}

	// 更新 ProbesMapKName 中的探测器（因为我们修改了 Fallbacks）
	for i := range vs.Probes {
		vs.ProbesMapKName[vs.Probes[i].Name] = vs.Probes[i]
	}
}

// InitializeGlobalVScan 初始化全局VScan实例（线程安全，只执行一次）
func InitializeGlobalVScan() {
	vscanOnce.Do(func() {
		globalVScan = VScan{}
		globalVScan.Init()

		// 获取并检查 NULL 探测器
		if nullProbe, ok := globalVScan.ProbesMapKName["NULL"]; ok {
			globalNull = &nullProbe
		}

		// 获取并检查 GenericLines 探测器
		if genericProbe, ok := globalVScan.ProbesMapKName["GenericLines"]; ok {
			globalCommon = &genericProbe
		}
	})
}

// GetGlobalVScan 获取全局VScan实例
func GetGlobalVScan() *VScan {
	InitializeGlobalVScan() // 确保已初始化
	return &globalVScan
}

// GetNullProbe 获取NULL探测器
func GetNullProbe() *Probe {
	InitializeGlobalVScan() // 确保已初始化
	return globalNull
}

// GetCommonProbe 获取通用探测器
func GetCommonProbe() *Probe {
	InitializeGlobalVScan() // 确保已初始化
	return globalCommon
}

func init() {
	InitializeGlobalVScan()
}
