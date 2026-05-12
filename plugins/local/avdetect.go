//go:build (plugin_avdetect || !plugin_selective) && !no_local

package local

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

//go:embed auto.json
var avDatabase []byte

// AVProduct AV产品信息结构
type AVProduct struct {
	Processes []string `json:"processes"`
	URL       string   `json:"url"`
}

// AVDetectPlugin 杀软检测插件
// 设计哲学："做一件事并做好" - 专注AV检测
// - 使用JSON数据库加载AV信息
// - 删除复杂的结果结构体
// - 跨平台支持，运行时适配
type AVDetectPlugin struct {
	plugins.BasePlugin
	avProducts map[string]AVProduct
}

// NewAVDetectPlugin 创建AV检测插件
func NewAVDetectPlugin() *AVDetectPlugin {
	plugin := &AVDetectPlugin{
		BasePlugin: plugins.NewBasePlugin("avdetect"),
		avProducts: make(map[string]AVProduct),
	}

	// 加载AV数据库
	if err := json.Unmarshal(avDatabase, &plugin.avProducts); err != nil {
		common.LogError(i18n.Tr("avdetect_load_failed", err))
	} else {
		common.LogInfo(i18n.Tr("avdetect_loaded", len(plugin.avProducts)))
	}

	return plugin
}

// Scan 执行AV/EDR检测 - 直接、有效
func (p *AVDetectPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	var output strings.Builder
	var detectedAVs []string

	output.WriteString("=== AV/EDR检测 ===\n")

	// 获取运行进程
	processes := p.getRunningProcesses()
	if len(processes) == 0 {
		return &plugins.Result{
			Success: false,
			Output:  "无法获取进程列表",
			Error:   fmt.Errorf("进程列表获取失败"),
		}
	}

	_, _ = fmt.Fprintf(&output, "扫描进程数: %d\n\n", len(processes))

	// 检测AV产品 - 使用JSON数据库
	for avName, avProduct := range p.avProducts {
		var foundProcesses []string

		for _, avProcess := range avProduct.Processes {
			for _, runningProcess := range processes {
				// 提取进程名部分进行匹配（去除PID信息）
				processName := runningProcess
				if strings.Contains(runningProcess, " (PID: ") {
					processName = strings.Split(runningProcess, " (PID: ")[0]
				}

				// 简单字符串匹配，忽略大小写
				if strings.Contains(strings.ToLower(processName), strings.ToLower(avProcess)) {
					foundProcesses = append(foundProcesses, runningProcess)
				}
			}
		}

		if len(foundProcesses) > 0 {
			detectedAVs = append(detectedAVs, avName)
			_, _ = fmt.Fprintf(&output, "✓ 检测到 %s:\n", avName)

			common.LogSuccess(i18n.Tr("avdetect_found", avName, len(foundProcesses)))

			// 输出详细进程信息到控制台
			for _, proc := range foundProcesses {
				_, _ = fmt.Fprintf(&output, "  - %s\n", proc)
				common.LogInfo(i18n.Tr("avdetect_process", proc))
			}
			output.WriteString("\n")
		}
	}

	// 统计结果
	output.WriteString("=== 检测结果 ===\n")
	_, _ = fmt.Fprintf(&output, "检测到的AV产品: %d个\n", len(detectedAVs))

	if len(detectedAVs) > 0 {
		output.WriteString("检测到的产品: " + strings.Join(detectedAVs, ", ") + "\n")
	} else {
		output.WriteString("未检测到已知的AV/EDR产品\n")
	}

	return &plugins.Result{
		Success: len(detectedAVs) > 0,
		Output:  output.String(),
		Error:   nil,
	}
}

// getRunningProcesses 获取运行进程列表 - 跨平台适配
func (p *AVDetectPlugin) getRunningProcesses() []string {
	var processes []string

	switch runtime.GOOS {
	case "windows":
		processes = p.getWindowsProcesses()
	case "linux", "darwin":
		processes = p.getUnixProcesses()
	default:
		// 不支持的平台，返回空列表
		return processes
	}

	return processes
}

// getWindowsProcesses 获取Windows进程 - 包含PID和进程名
func (p *AVDetectPlugin) getWindowsProcesses() []string {
	var processes []string

	// 使用tasklist命令
	cmd := exec.Command("tasklist", "/fo", "csv", "/nh")
	output, err := cmd.Output()
	if err != nil {
		return processes
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 解析CSV格式：进程名,PID,会话名,会话号,内存
		if strings.HasPrefix(line, "\"") {
			parts := strings.Split(line, "\",\"")
			if len(parts) >= 2 {
				processName := strings.Trim(parts[0], "\"")
				pid := strings.Trim(parts[1], "\"")
				if processName != "" && pid != "" {
					// 格式：进程名 (PID: xxxx)
					processInfo := fmt.Sprintf("%s (PID: %s)", processName, pid)
					processes = append(processes, processInfo)
				}
			}
		}
	}

	return processes
}

// getUnixProcesses 获取Unix进程 - 简化实现
func (p *AVDetectPlugin) getUnixProcesses() []string {
	var processes []string

	// 使用ps命令
	cmd := exec.Command("ps", "-eo", "comm")
	output, err := cmd.Output()
	if err != nil {
		return processes
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && line != "COMMAND" {
			processes = append(processes, line)
		}
	}

	return processes
}

// 注册插件
func init() {
	RegisterLocalPlugin("avdetect", func() Plugin {
		return NewAVDetectPlugin()
	})
}
