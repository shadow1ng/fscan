//go:build (plugin_keylogger || !plugin_selective) && !no_local

package local

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// KeyloggerPlugin 键盘记录插件
// 设计哲学：直接实现，删除过度设计
// - 删除复杂的继承体系
// - 直接实现键盘记录功能
// - 保持原有功能逻辑
type KeyloggerPlugin struct {
	plugins.BasePlugin
	keyBuffer   []string
	bufferMutex sync.RWMutex
}

// NewKeyloggerPlugin 创建键盘记录插件
func NewKeyloggerPlugin() *KeyloggerPlugin {
	return &KeyloggerPlugin{
		BasePlugin: plugins.NewBasePlugin("keylogger"),
		keyBuffer:  make([]string, 0),
	}
}

// Scan 执行键盘记录 - 直接实现
func (p *KeyloggerPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	config := session.Config
	var output strings.Builder

	// 从config获取配置
	outputFile := config.LocalExploit.KeyloggerOutputFile
	if outputFile == "" {
		outputFile = "keylog.txt"
	}

	output.WriteString("=== 键盘记录 ===\n")
	output.WriteString(fmt.Sprintf("输出文件: %s\n", outputFile))
	output.WriteString(fmt.Sprintf("平台: %s\n\n", runtime.GOOS))

	// 检查输出文件权限
	if err := p.checkOutputFilePermissions(outputFile); err != nil {
		output.WriteString(fmt.Sprintf("输出文件权限检查失败: %v\n", err))
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	// 检查平台要求
	if err := p.checkPlatformRequirements(); err != nil {
		output.WriteString(fmt.Sprintf("平台要求检查失败: %v\n", err))
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	// 启动键盘记录
	err := p.startKeylogging(ctx, outputFile)
	if err != nil {
		output.WriteString(fmt.Sprintf("键盘记录失败: %v\n", err))
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	// 输出结果
	output.WriteString("✓ 键盘记录已完成\n")
	output.WriteString(fmt.Sprintf("捕获事件数: %d\n", len(p.keyBuffer)))
	output.WriteString(fmt.Sprintf("日志文件: %s\n", outputFile))

	common.LogSuccess(i18n.Tr("keylogger_success", len(p.keyBuffer)))

	return &plugins.Result{
		Success: true,
		Type:    plugins.ResultTypeService,
		Output:  output.String(),
		Error:   nil,
	}
}

// startKeylogging 启动键盘记录
func (p *KeyloggerPlugin) startKeylogging(ctx context.Context, outputFile string) error {

	// 根据平台启动相应的键盘记录
	var err error
	switch runtime.GOOS {
	case "windows":
		err = p.startWindowsKeylogging(ctx)
	case "linux":
		err = p.startLinuxKeylogging(ctx)
	case "darwin":
		err = p.startDarwinKeylogging(ctx)
	default:
		err = fmt.Errorf("不支持的平台: %s", runtime.GOOS)
	}

	if err != nil {
		return fmt.Errorf("键盘记录失败: %w", err)
	}

	// 保存到文件
	if err := p.saveKeysToFile(outputFile); err != nil {
		common.LogError(i18n.Tr("keylogger_save_failed", err))
	}

	return nil
}

// checkOutputFilePermissions 检查输出文件权限
func (p *KeyloggerPlugin) checkOutputFilePermissions(outputFile string) error {
	file, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("无法创建输出文件 %s: %w", outputFile, err)
	}
	_ = file.Close()
	return nil
}

// checkPlatformRequirements 检查平台特定要求
func (p *KeyloggerPlugin) checkPlatformRequirements() error {
	switch runtime.GOOS {
	case "windows":
		return p.checkWindowsRequirements()
	case "linux":
		return p.checkLinuxRequirements()
	case "darwin":
		return p.checkDarwinRequirements()
	default:
		return fmt.Errorf("不支持的平台: %s", runtime.GOOS)
	}
}

// addKeyToBuffer 添加按键到缓冲区
func (p *KeyloggerPlugin) addKeyToBuffer(key string) {
	p.bufferMutex.Lock()
	defer p.bufferMutex.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	entry := fmt.Sprintf("[%s] %s", timestamp, key)
	p.keyBuffer = append(p.keyBuffer, entry)
}

// saveKeysToFile 保存键盘记录到文件
func (p *KeyloggerPlugin) saveKeysToFile(outputFile string) error {
	p.bufferMutex.RLock()
	defer p.bufferMutex.RUnlock()

	if len(p.keyBuffer) == 0 {
		common.LogInfo(i18n.GetText("keylogger_no_input"))
		return nil
	}

	file, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("无法打开输出文件: %w", err)
	}
	defer func() { _ = file.Close() }()

	// 写入头部信息
	header := "=== 键盘记录日志 ===\n"
	header += fmt.Sprintf("开始时间: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	header += fmt.Sprintf("平台: %s\n", runtime.GOOS)
	header += fmt.Sprintf("捕获事件数: %d\n", len(p.keyBuffer))
	header += "========================\n\n"

	if _, err := file.WriteString(header); err != nil {
		return fmt.Errorf("写入头部信息失败: %w", err)
	}

	// 写入键盘记录
	for _, entry := range p.keyBuffer {
		if _, err := file.WriteString(entry + "\n"); err != nil {
			return fmt.Errorf("写入键盘记录失败: %w", err)
		}
	}

	return nil
}

// 平台特定的键盘记录实现 - 简化版本，仅做演示
func (p *KeyloggerPlugin) startWindowsKeylogging(ctx context.Context) error {
	// Windows平台键盘记录实现
	// 在实际实现中需要使用Windows API
	p.addKeyToBuffer("演示键盘记录 - Windows平台")

	// 模拟记录一段时间
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
		// 模拟结束
	}

	return nil
}

func (p *KeyloggerPlugin) startLinuxKeylogging(ctx context.Context) error {
	// Linux平台键盘记录实现
	// 在实际实现中需要访问/dev/input/event*设备
	p.addKeyToBuffer("演示键盘记录 - Linux平台")

	// 模拟记录一段时间
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
		// 模拟结束
	}

	return nil
}

func (p *KeyloggerPlugin) startDarwinKeylogging(ctx context.Context) error {
	// macOS平台键盘记录实现
	// 在实际实现中需要使用Core Graphics框架
	p.addKeyToBuffer("演示键盘记录 - macOS平台")

	// 模拟记录一段时间
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
		// 模拟结束
	}

	return nil
}

// 平台特定的要求检查 - 简化版本
func (p *KeyloggerPlugin) checkWindowsRequirements() error {
	// Windows平台要求检查
	return nil
}

func (p *KeyloggerPlugin) checkLinuxRequirements() error {
	// Linux平台要求检查
	return nil
}

func (p *KeyloggerPlugin) checkDarwinRequirements() error {
	// macOS平台要求检查
	return nil
}

// 注册插件
func init() {
	RegisterLocalPlugin("keylogger", func() Plugin {
		return NewKeyloggerPlugin()
	})
}
