package common

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/shadow1ng/fscan/common/i18n"
)

// 默认终端宽度
const defaultTerminalWidth = 80

/*
ProgressManager.go - 固定底部进度条管理器

提供固定在终端底部的进度条显示，与正常输出内容分离。
使用终端控制码实现位置固定和内容保护。
*/

// ProgressManager 进度条管理器
type ProgressManager struct {
	mu              sync.RWMutex
	enabled         bool
	total           int64
	current         int64
	description     string
	startTime       time.Time
	isActive        bool
	terminalHeight  int
	reservedLines   int // 为进度条保留的行数
	lastContentLine int // 最后一行内容的位置

	// 输出缓冲相关
	outputMutex sync.Mutex

	// 活跃指示器相关
	spinnerIndex     int
	lastActivity     time.Time
	activityTicker   *time.Ticker
	stopActivityChan chan struct{}

	// 进度条更新控制（减少 Windows 终端的重复输出）
	lastRenderedPercent int

	// 引用，避免读全局
	state   *State
	noColor bool
}

// =============================================================================
// ANSI终端控制码常量
// =============================================================================

const (
	// AnsiClearLine 光标和行控制 - 清除当前行并回到行首
	AnsiClearLine = "\033[2K\r"
	// AnsiMoveCursor 向上移动N行（格式化字符串）
	AnsiMoveCursor = "\033[%dA"

	// AnsiRed 颜色代码 - 红色文本
	AnsiRed = "\033[31m"
	// AnsiGreen 绿色文本
	AnsiGreen = "\033[32m"
	// AnsiYellow 黄色文本
	AnsiYellow = "\033[33m"
	// AnsiCyan 青色文本
	AnsiCyan = "\033[36m"
	// AnsiGray 灰色文本
	AnsiGray = "\033[90m"
	// AnsiReset 重置所有属性
	AnsiReset = "\033[0m"
)

var (
	globalProgressManager *ProgressManager
	progressMutex         sync.Mutex

	// 活跃指示器字符序列（旋转动画）
	spinnerChars = []string{"|", "/", "-", "\\"}

	// 活跃指示器更新间隔
	activityUpdateInterval = 500 * time.Millisecond
)

// GetProgressManager 获取全局进度条管理器
func GetProgressManager() *ProgressManager {
	progressMutex.Lock()
	defer progressMutex.Unlock()

	if globalProgressManager == nil {
		globalProgressManager = &ProgressManager{
			enabled:        true,
			reservedLines:  2, // 保留2行：进度条 + 空行
			terminalHeight: getTerminalHeight(),
		}
	}
	return globalProgressManager
}

// InitProgress 初始化进度条
func (pm *ProgressManager) InitProgress(total int64, description string) {
	cfg := GetGlobalConfig()
	if cfg.Output.DisableProgress || cfg.Output.Silent {
		pm.enabled = false
		return
	}
	pm.state = GetGlobalState()
	pm.noColor = cfg.Output.NoColor

	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.total = total
	pm.current = 0
	pm.description = description
	pm.startTime = time.Now()
	pm.isActive = true
	pm.enabled = true
	pm.lastActivity = time.Now()
	pm.spinnerIndex = 0
	pm.lastRenderedPercent = -1 // 强制首次渲染

	// 为进度条保留空间
	pm.setupProgressSpace()

	// 启动活跃指示器
	pm.startActivityIndicator()

	// 初始显示进度条
	pm.renderProgress()
}

// UpdateProgress 更新进度
func (pm *ProgressManager) UpdateProgress(increment int64) {
	if !pm.enabled || !pm.isActive {
		return
	}

	// 原子累加，避免高并发下的锁竞争
	newCurrent := atomic.AddInt64(&pm.current, increment)
	if newCurrent > pm.total {
		atomic.StoreInt64(&pm.current, pm.total)
	}

	// 节流渲染：距上次渲染不足 50ms 则跳过
	now := time.Now()
	pm.mu.RLock()
	lastAct := pm.lastActivity
	pm.mu.RUnlock()
	if now.Sub(lastAct) < 50*time.Millisecond {
		return
	}

	pm.mu.Lock()
	pm.lastActivity = now
	pm.mu.Unlock()

	pm.renderProgress()
}

// =============================================================================================
// 已删除的死代码（未使用）：SetProgress 设置当前进度
// =============================================================================================

// FinishProgress 完成进度条
func (pm *ProgressManager) FinishProgress() {
	if !pm.enabled || !pm.isActive {
		return
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	atomic.StoreInt64(&pm.current, pm.total)
	pm.renderProgress()

	// 停止活跃指示器
	pm.stopActivityIndicator()

	// 显示完成信息
	pm.showCompletionInfo()

	// 清理进度条区域，恢复正常输出
	pm.clearProgressArea()
	pm.isActive = false
}

// setupProgressSpace 设置进度条空间
func (pm *ProgressManager) setupProgressSpace() {
	// 简化设计：进度条在原地更新，不需要预留额外空间
	// 只是标记进度条开始的位置
	pm.lastContentLine = 0
}

// =============================================================================================
// 已删除的死代码（未使用）：moveToContentArea 和 moveToProgressLine 方法
// =============================================================================================

// renderProgress 渲染进度条（使用锁避免输出冲突）
func (pm *ProgressManager) renderProgress() {
	pm.outputMutex.Lock()
	defer pm.outputMutex.Unlock()

	pm.renderProgressUnsafe()
}

// generateProgressBar 生成进度条字符串
// 根据终端宽度动态调整内容，确保不超过一行
func (pm *ProgressManager) generateProgressBar() string {
	termWidth := getTerminalWidth()

	// 获取发包统计
	packetInfo := pm.getPacketInfo()

	if pm.total == 0 {
		spinner := pm.getActivityIndicator()
		base := fmt.Sprintf("%s %s 等待中...", pm.description, spinner)
		if packetInfo != "" {
			return base + " " + packetInfo
		}
		return base
	}

	percentage := float64(atomic.LoadInt64(&pm.current)) / float64(pm.total) * 100
	elapsed := time.Since(pm.startTime)
	current := atomic.LoadInt64(&pm.current)

	// 计算速度
	speed := float64(current) / elapsed.Seconds()
	speedStr := ""
	if speed > 0 {
		speedStr = fmt.Sprintf(" %.0f/s", speed)
	}

	// 计算预估剩余时间
	var eta string
	if current > 0 && current < pm.total {
		totalTime := elapsed * time.Duration(pm.total) / time.Duration(current)
		remaining := totalTime - elapsed
		if remaining > 0 {
			eta = fmt.Sprintf(" ETA:%s", formatDuration(remaining))
		}
	}

	// 活跃指示器
	spinner := pm.getActivityIndicator()

	// 计算固定部分的宽度
	fixedPart := fmt.Sprintf("%s %s %5.1f%% [] (%d/%d)%s%s %s",
		pm.description, spinner, percentage, current, pm.total, speedStr, eta, packetInfo)
	fixedWidth := displayWidth(fixedPart)

	// 计算进度条槽位可用宽度（预留2字符余量）
	barWidth := termWidth - fixedWidth - 2
	if barWidth < 10 {
		barWidth = 10 // 最小进度条宽度
	}
	if barWidth > 30 {
		barWidth = 30 // 最大进度条宽度
	}

	// 生成进度条
	filled := int(percentage * float64(barWidth) / 100)
	if filled > barWidth {
		filled = barWidth
	}

	bar := "[" + strings.Repeat("=", filled)
	if filled < barWidth {
		bar += ">"
		bar += strings.Repeat("-", barWidth-filled-1)
	}
	bar += "]"

	// 构建最终进度条
	result := fmt.Sprintf("%s %s %5.1f%% %s (%d/%d)%s%s",
		pm.description, spinner, percentage, bar, current, pm.total, speedStr, eta)

	if packetInfo != "" {
		result += " " + packetInfo
	}

	return result
}

// getPacketInfo 获取发包统计信息（简化版）
func (pm *ProgressManager) getPacketInfo() string {
	if pm.state == nil {
		return ""
	}
	packetCount := pm.state.GetPacketCount()
	if packetCount == 0 {
		return ""
	}

	tcpSuccess := pm.state.GetTCPSuccessPacketCount()
	tcpFailed := pm.state.GetTCPFailedPacketCount()

	// 简化格式：TCP:成功/失败
	if tcpSuccess > 0 || tcpFailed > 0 {
		return fmt.Sprintf("TCP:%d/%d", tcpSuccess, tcpFailed)
	}

	return fmt.Sprintf("Pkt:%d", packetCount)
}

// showCompletionInfo 显示完成信息
func (pm *ProgressManager) showCompletionInfo() {
	elapsed := time.Since(pm.startTime)

	// 换行并显示完成信息
	fmt.Print("\n")

	completionMsg := i18n.GetText("progress_scan_completed")
	if pm.noColor {
		fmt.Printf("[完成] %s %d/%d (耗时: %s)\n",
			completionMsg, pm.total, pm.total, formatDuration(elapsed))
	} else {
		fmt.Printf("%s[完成] %s %d/%d%s %s(耗时: %s)%s\n",
			AnsiGreen, completionMsg, pm.total, pm.total, AnsiReset,
			AnsiGray, formatDuration(elapsed), AnsiReset)
	}
}

// clearProgressArea 清理进度条区域
func (pm *ProgressManager) clearProgressArea() {
	// 简单清除当前行
	fmt.Print(AnsiClearLine)
}

// IsActive 检查进度条是否活跃
func (pm *ProgressManager) IsActive() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.isActive && pm.enabled
}

// getTerminalHeight 获取终端高度
func getTerminalHeight() int {
	return 0
}

// getTerminalWidth 获取终端宽度
func getTerminalWidth() int {
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width <= 0 {
		return defaultTerminalWidth
	}
	return width
}

// displayWidth 计算字符串的显示宽度（中文字符占2列）
func displayWidth(s string) int {
	width := 0
	for _, r := range s {
		if r >= 0x4E00 && r <= 0x9FFF || // CJK统一汉字
			r >= 0x3000 && r <= 0x303F || // CJK标点
			r >= 0xFF00 && r <= 0xFFEF { // 全角字符
			width += 2
		} else if r >= 0x2600 && r <= 0x27BF || // 杂项符号
			r >= 0x2700 && r <= 0x27BF { // 装饰符号
			width += 2
		} else {
			width += 1
		}
	}
	return width
}

// truncateToWidth 截断字符串到指定显示宽度
func truncateToWidth(s string, maxWidth int) string {
	if maxWidth <= 0 {
		return ""
	}

	currentWidth := 0
	result := strings.Builder{}

	for _, r := range s {
		var charWidth int
		if r >= 0x4E00 && r <= 0x9FFF ||
			r >= 0x3000 && r <= 0x303F ||
			r >= 0xFF00 && r <= 0xFFEF ||
			r >= 0x2600 && r <= 0x27BF ||
			r >= 0x2700 && r <= 0x27BF {
			charWidth = 2
		} else {
			charWidth = 1
		}

		if currentWidth+charWidth > maxWidth {
			break
		}
		result.WriteRune(r)
		currentWidth += charWidth
	}

	return result.String()
}

// stripAnsiCodes 移除 ANSI 转义码，用于计算实际显示宽度
func stripAnsiCodes(s string) string {
	result := strings.Builder{}
	inEscape := false

	for i := 0; i < len(s); {
		if s[i] == '\033' && i+1 < len(s) && s[i+1] == '[' {
			inEscape = true
			i += 2
			continue
		}
		if inEscape {
			if (s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z') {
				inEscape = false
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		result.WriteRune(r)
		i += size
	}

	return result.String()
}

// formatDuration 格式化时间间隔
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.1fm", d.Minutes())
	}
	return fmt.Sprintf("%.1fh", d.Hours())
}

// InitProgressBar 初始化进度条（全局函数，方便其他模块调用）
func InitProgressBar(total int64, description string) {
	GetProgressManager().InitProgress(total, description)
}

// UpdateProgressBar 更新进度条
func UpdateProgressBar(increment int64) {
	GetProgressManager().UpdateProgress(increment)
}

// =============================================================================================
// 已删除的死代码（未使用）：SetProgressBar 全局函数
// =============================================================================================

// FinishProgressBar 完成进度条
func FinishProgressBar() {
	GetProgressManager().FinishProgress()
}

// IsProgressActive 检查进度条是否活跃
func IsProgressActive() bool {
	return GetProgressManager().IsActive()
}

// GetProgressPercent 获取当前进度百分比 (0-100)
func GetProgressPercent() float64 {
	return GetProgressManager().GetPercent()
}

// GetPercent 获取当前进度百分比
func (pm *ProgressManager) GetPercent() float64 {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if !pm.isActive || pm.total == 0 {
		return 0
	}
	return float64(atomic.LoadInt64(&pm.current)) / float64(pm.total) * 100
}

// =============================================================================
// 日志输出协调功能
// =============================================================================

// LogWithProgress 在进度条活跃时协调日志输出
func LogWithProgress(message string) {
	if cfg := GetGlobalConfig(); cfg != nil && cfg.Output.Silent {
		return
	}

	pm := GetProgressManager()
	if !pm.IsActive() {
		// 如果进度条不活跃，直接输出
		fmt.Println(message)
		return
	}

	pm.outputMutex.Lock()
	defer pm.outputMutex.Unlock()

	// 清除当前行（清除进度条）
	// Windows 通过 progress_manager_win.go 已启用 ANSI 支持
	fmt.Print(AnsiClearLine)

	// 输出日志消息
	fmt.Println(message)

	// 不重绘进度条，等待下次 UpdateProgress 自动绘制
}

// renderProgressUnsafe 不加锁的进度条渲染（内部使用）
func (pm *ProgressManager) renderProgressUnsafe() {
	if !pm.enabled || !pm.isActive {
		return
	}

	// 计算当前百分比（避免除零）
	currentPercent := 0
	if pm.total > 0 {
		currentPercent = int((atomic.LoadInt64(&pm.current) * 100) / pm.total)
	}

	// 只在百分比变化时更新，减少不必要的渲染
	if currentPercent == pm.lastRenderedPercent && currentPercent < 100 {
		return
	}
	pm.lastRenderedPercent = currentPercent

	// 获取终端宽度
	termWidth := getTerminalWidth()

	// 生成进度条内容
	progressBar := pm.generateProgressBar()

	// 计算实际显示宽度（去除 ANSI 码后）
	plainBar := stripAnsiCodes(progressBar)
	actualWidth := displayWidth(plainBar)

	// 如果超过终端宽度，截断内容
	// 预留 1 字符防止边界问题
	maxWidth := termWidth - 1
	if actualWidth > maxWidth {
		// 截断纯文本部分
		progressBar = truncateToWidth(plainBar, maxWidth)
	}

	// 清除当前行并移动到行首
	// 使用空格覆盖旧内容，确保不留残留
	clearStr := "\r" + strings.Repeat(" ", termWidth-1) + "\r"
	fmt.Print(clearStr)

	// 输出进度条（带颜色，如果启用）
	if pm.noColor {
		fmt.Print(progressBar)
	} else {
		fmt.Printf("%s%s%s", AnsiCyan, progressBar, AnsiReset)
	}

	// 刷新输出
	_ = os.Stdout.Sync()
}

// =============================================================================
// 活跃指示器相关方法
// =============================================================================

// startActivityIndicator 启动活跃指示器
func (pm *ProgressManager) startActivityIndicator() {
	// 防止重复启动
	if pm.activityTicker != nil {
		return
	}

	pm.activityTicker = time.NewTicker(activityUpdateInterval)
	pm.stopActivityChan = make(chan struct{})

	go func() {
		for {
			select {
			case <-pm.activityTicker.C:
				// 只有在活跃状态下才更新指示器
				if pm.isActive && pm.enabled {
					pm.mu.Lock()
					pm.spinnerIndex = (pm.spinnerIndex + 1) % len(spinnerChars)
					pm.mu.Unlock()

					// 只有在长时间没有进度更新时才重新渲染
					// 这样可以避免频繁更新时的性能问题
					if time.Since(pm.lastActivity) > 2*time.Second {
						pm.renderProgress()
					}
				}
			case <-pm.stopActivityChan:
				return
			}
		}
	}()
}

// stopActivityIndicator 停止活跃指示器
func (pm *ProgressManager) stopActivityIndicator() {
	if pm.activityTicker != nil {
		pm.activityTicker.Stop()
		pm.activityTicker = nil
	}

	if pm.stopActivityChan != nil {
		close(pm.stopActivityChan)
		pm.stopActivityChan = nil
	}
}

// getActivityIndicator 获取当前活跃指示器字符
func (pm *ProgressManager) getActivityIndicator() string {
	// 如果最近有活动（2秒内），显示静态指示器
	if time.Since(pm.lastActivity) <= 2*time.Second {
		return "●" // 实心圆表示活跃
	}

	// 如果长时间没有活动，显示旋转指示器表明程序仍在运行
	return spinnerChars[pm.spinnerIndex]
}

// =============================================================================
// 并发监控器 (从 concurrency_monitor.go 合并)
// =============================================================================

/*
ConcurrencyMonitor - 并发监控器

监控两个层级的并发：
1. 主扫描器线程数 (-t 参数控制)
2. 插件内连接线程数 (-mt 参数控制)
*/

// ConcurrencyMonitor 并发监控器
type ConcurrencyMonitor struct {
	// 主扫描器层级
	activePluginTasks int64 // 当前活跃的插件任务数
	totalPluginTasks  int64 // 总插件任务数

	// 插件内连接层级已移除 - 原代码为死代码，无任何调用者
}

// 已移除 PluginConnectionInfo 结构体 - 原为死代码，无任何使用

var (
	globalConcurrencyMonitor *ConcurrencyMonitor
	concurrencyMutex         sync.Once
)

// GetConcurrencyMonitor 获取全局并发监控器
func GetConcurrencyMonitor() *ConcurrencyMonitor {
	concurrencyMutex.Do(func() {
		globalConcurrencyMonitor = &ConcurrencyMonitor{
			activePluginTasks: 0,
			totalPluginTasks:  0,
		}
	})
	return globalConcurrencyMonitor
}

// =============================================================================
// 主扫描器层级监控
// =============================================================================

// StartPluginTask 开始插件任务
func (m *ConcurrencyMonitor) StartPluginTask() {
	atomic.AddInt64(&m.activePluginTasks, 1)
	atomic.AddInt64(&m.totalPluginTasks, 1)
}

// FinishPluginTask 完成插件任务
func (m *ConcurrencyMonitor) FinishPluginTask() {
	atomic.AddInt64(&m.activePluginTasks, -1)
}

// GetPluginTaskStats 获取插件任务统计
func (m *ConcurrencyMonitor) GetPluginTaskStats() (active int64, total int64) {
	return atomic.LoadInt64(&m.activePluginTasks), atomic.LoadInt64(&m.totalPluginTasks)
}

// =============================================================================
// 已移除插件内连接层级监控 - 原为死代码，无任何调用者
// =============================================================================

// 已移除未使用的 Reset 方法

// GetConcurrencyStatus 获取并发状态字符串
func (m *ConcurrencyMonitor) GetConcurrencyStatus() string {
	activePlugins, _ := m.GetPluginTaskStats()

	if activePlugins == 0 {
		return ""
	}

	return fmt.Sprintf("%s:%d", i18n.GetText("concurrency_plugin"), activePlugins)
}

// 已移除未使用的 GetDetailedStatus 方法
