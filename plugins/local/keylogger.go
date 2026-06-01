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

	output.WriteString(i18n.GetText("keylogger_header") + "\n")
	output.WriteString(i18n.Tr("local_output_file", outputFile) + "\n")
	output.WriteString(i18n.Tr("local_platform", runtime.GOOS) + "\n\n")

	// 检查输出文件权限
	if err := p.checkOutputFilePermissions(outputFile); err != nil {
		output.WriteString(i18n.Tr("keylogger_output_permission_failed", err) + "\n")
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	// 检查平台要求
	if err := p.checkPlatformRequirements(); err != nil {
		output.WriteString(i18n.Tr("platform_requirement_failed", err) + "\n")
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	// 启动键盘记录
	err := p.startKeylogging(ctx, outputFile, session)
	if err != nil {
		output.WriteString(i18n.Tr("keylogger_failed", err) + "\n")
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	// 输出结果
	output.WriteString(i18n.GetText("keylogger_done") + "\n")
	output.WriteString(i18n.Tr("keylogger_event_count", len(p.keyBuffer)) + "\n")
	output.WriteString(i18n.Tr("keylogger_log_file", outputFile) + "\n")

	session.LogSuccess(i18n.Tr("keylogger_success", len(p.keyBuffer)))

	return &plugins.Result{
		Success: true,
		Type:    plugins.ResultTypeService,
		Output:  output.String(),
		Error:   nil,
	}
}

// startKeylogging 启动键盘记录
func (p *KeyloggerPlugin) startKeylogging(ctx context.Context, outputFile string, session *common.ScanSession) error {

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
		err = fmt.Errorf("%s", i18n.Tr("unsupported_platform", runtime.GOOS))
	}

	if err != nil {
		return fmt.Errorf("%s: %w", i18n.GetText("keylogger_failed_plain"), err)
	}

	// 保存到文件
	if err := p.saveKeysToFile(outputFile, session); err != nil {
		session.LogError(i18n.Tr("keylogger_save_failed", err))
	}

	return nil
}

// checkOutputFilePermissions 检查输出文件权限
func (p *KeyloggerPlugin) checkOutputFilePermissions(outputFile string) error {
	file, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.Tr("output_file_create_failed", outputFile), err)
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
		return fmt.Errorf("%s", i18n.Tr("unsupported_platform", runtime.GOOS))
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
func (p *KeyloggerPlugin) saveKeysToFile(outputFile string, session *common.ScanSession) error {
	p.bufferMutex.RLock()
	defer p.bufferMutex.RUnlock()

	if len(p.keyBuffer) == 0 {
		session.LogInfo(i18n.GetText("keylogger_no_input"))
		return nil
	}

	file, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.GetText("output_file_open_failed"), err)
	}
	defer func() { _ = file.Close() }()

	// 写入头部信息
	header := i18n.GetText("keylogger_log_header") + "\n"
	header += i18n.Tr("local_start_time", time.Now().Format("2006-01-02 15:04:05")) + "\n"
	header += i18n.Tr("local_platform", runtime.GOOS) + "\n"
	header += i18n.Tr("keylogger_event_count", len(p.keyBuffer)) + "\n"
	header += "========================\n\n"

	if _, err := file.WriteString(header); err != nil {
		return fmt.Errorf("%s: %w", i18n.GetText("keylogger_header_write_failed"), err)
	}

	// 写入键盘记录
	for _, entry := range p.keyBuffer {
		if _, err := file.WriteString(entry + "\n"); err != nil {
			return fmt.Errorf("%s: %w", i18n.GetText("keylogger_entry_write_failed"), err)
		}
	}

	return nil
}

// 平台特定的键盘记录实现 - 简化版本，仅做演示
func (p *KeyloggerPlugin) startWindowsKeylogging(ctx context.Context) error {
	// Windows平台键盘记录实现
	// 在实际实现中需要使用Windows API
	p.addKeyToBuffer(i18n.GetText("keylogger_demo_windows"))

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
	p.addKeyToBuffer(i18n.GetText("keylogger_demo_linux"))

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
	p.addKeyToBuffer(i18n.GetText("keylogger_demo_darwin"))

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
