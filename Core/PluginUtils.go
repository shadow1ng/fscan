package Core

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"strings"
)

// 插件列表解析和验证
func parsePluginList(pluginStr string) []string {
	if pluginStr == "" {
		return nil
	}

	// 按逗号分割并去除每个插件名称两端的空白
	plugins := strings.Split(pluginStr, ",")
	for i, p := range plugins {
		plugins[i] = strings.TrimSpace(p)
	}

	// 过滤空字符串
	var result []string
	for _, p := range plugins {
		if p != "" {
			result = append(result, p)
		}
	}

	return result
}

// 验证扫描插件的有效性
func validateScanPlugins() error {
	// 如果未指定扫描模式或使用All模式，则无需验证
	if Common.ScanMode == "" || Common.ScanMode == "all" {
		return nil
	}

	// 解析插件列表
	plugins := parsePluginList(Common.ScanMode)
	if len(plugins) == 0 {
		plugins = []string{Common.ScanMode}
	}

	// 验证每个插件是否有效
	var invalidPlugins []string
	for _, plugin := range plugins {
		if _, exists := Common.PluginManager[plugin]; !exists {
			invalidPlugins = append(invalidPlugins, plugin)
		}
	}

	if len(invalidPlugins) > 0 {
		return fmt.Errorf("无效的插件: %s", strings.Join(invalidPlugins, ", "))
	}

	return nil
}
