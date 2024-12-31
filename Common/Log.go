package Common

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

var (
	// 全局变量
	status  = &ScanStatus{lastSuccess: time.Now(), lastError: time.Now()}
	results = make(chan *LogEntry, 1000) // 使用缓冲通道
	logWG   sync.WaitGroup

	// 扫描计数
	Num int64 // 总任务数
	End int64 // 已完成任务数
)

// 将 results 改名为 Results 使其可导出
var (
	Results = results // 使 results 可导出
	LogWG   = logWG   // 使 logWG 可导出
)

// ScanStatus 记录扫描状态
type ScanStatus struct {
	mu          sync.RWMutex
	total       int64
	completed   int64
	lastSuccess time.Time
	lastError   time.Time
}

// LogEntry 日志条目
type LogEntry struct {
	Level   string // "ERROR", "INFO", "SUCCESS", "DEBUG"
	Time    time.Time
	Content string
}

// LogLevel 定义日志等级常量
const (
	LogLevelAll     = "ALL"     // 输出所有日志
	LogLevelError   = "ERROR"   // 错误日志
	LogLevelInfo    = "INFO"    // 信息日志
	LogLevelSuccess = "SUCCESS" // 成功日志
	LogLevelDebug   = "DEBUG"   // 调试日志
)

// 定义日志颜色映射
var logColors = map[string]color.Attribute{
	LogLevelError:   color.FgRed,
	LogLevelInfo:    color.FgYellow,
	LogLevelSuccess: color.FgGreen,
	LogLevelDebug:   color.FgBlue,
}

// bufferedFileWriter 文件写入器
type bufferedFileWriter struct {
	file    *os.File
	writer  *bufio.Writer
	jsonEnc *json.Encoder
}

func init() {
	log.SetOutput(io.Discard)
	go processLogs()
}

// formatLogMessage 格式化日志消息
func formatLogMessage(entry *LogEntry) string {
	timeStr := entry.Time.Format("2006-01-02 15:04:05")
	return fmt.Sprintf("[%s] [%s] %s", timeStr, entry.Level, entry.Content)
}

func printLog(entry *LogEntry) {
	// 根据配置的日志级别过滤
	if LogLevel != LogLevelAll && entry.Level != LogLevel {
		return
	}

	logMsg := formatLogMessage(entry)
	if NoColor {
		fmt.Println(logMsg)
		return
	}

	if colorAttr, ok := logColors[entry.Level]; ok {
		color.New(colorAttr).Println(logMsg)
	} else {
		fmt.Println(logMsg)
	}
}

// 同样修改 LogError 和 LogInfo
func LogError(errMsg string) {
	// 获取调用者信息
	_, file, line, ok := runtime.Caller(1)
	if !ok {
		file = "unknown"
		line = 0
	}
	// 只获取文件名
	file = filepath.Base(file)

	// 格式化错误消息
	errorMsg := fmt.Sprintf("%s:%d - %s", file, line, errMsg)

	select {
	case Results <- &LogEntry{
		Level:   LogLevelError,
		Time:    time.Now(),
		Content: errorMsg,
	}:
		logWG.Add(1)
	default:
		printLog(&LogEntry{
			Level:   LogLevelError,
			Time:    time.Now(),
			Content: errorMsg,
		})
	}
}

func LogInfo(msg string) {
	select {
	case Results <- &LogEntry{
		Level:   LogLevelInfo,
		Time:    time.Now(),
		Content: msg,
	}:
		logWG.Add(1)
	default:
		printLog(&LogEntry{
			Level:   LogLevelInfo,
			Time:    time.Now(),
			Content: msg,
		})
	}
}

// LogSuccess 记录成功信息
func LogSuccess(result string) {
	// 添加通道关闭检查
	select {
	case Results <- &LogEntry{
		Level:   LogLevelSuccess,
		Time:    time.Now(),
		Content: result,
	}:
		logWG.Add(1)
		status.mu.Lock()
		status.lastSuccess = time.Now()
		status.mu.Unlock()
	default:
		// 如果通道已关闭或已满，直接打印
		printLog(&LogEntry{
			Level:   LogLevelSuccess,
			Time:    time.Now(),
			Content: result,
		})
	}
}

// JsonOutput JSON输出的结构体
type JsonOutput struct {
	Level     string    `json:"level"`
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message"`
}

// processLogs 处理日志信息
func processLogs() {
	writer := newBufferedFileWriter()
	defer writer.close()

	for entry := range results {
		if !Silent {
			printLog(entry)
		}

		if writer != nil {
			writer.write(entry)
		}

		logWG.Done()
	}
}

func newBufferedFileWriter() *bufferedFileWriter {
	if DisableSave {
		return nil
	}

	file, err := os.OpenFile(Outputfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("[ERROR] 打开输出文件失败 %s: %v\n", Outputfile, err)
		return nil
	}

	writer := bufio.NewWriter(file)
	return &bufferedFileWriter{
		file:    file,
		writer:  writer,
		jsonEnc: json.NewEncoder(writer),
	}
}

func (w *bufferedFileWriter) write(entry *LogEntry) {
	if w == nil {
		return
	}

	if JsonFormat {
		output := JsonOutput{
			Level:     entry.Level,
			Timestamp: entry.Time,
			Message:   entry.Content,
		}
		if err := w.jsonEnc.Encode(output); err != nil {
			fmt.Printf("[ERROR] JSON编码失败: %v\n", err)
		}
	} else {
		logMsg := formatLogMessage(entry) + "\n"
		if _, err := w.writer.WriteString(logMsg); err != nil {
			fmt.Printf("[ERROR] 写入文件失败: %v\n", err)
		}
	}

	w.writer.Flush()
}

func (w *bufferedFileWriter) close() {
	if w != nil {
		w.writer.Flush()
		w.file.Close()
	}
}

// CheckErrs 检查是否为需要重试的错误
func CheckErrs(err error) error {
	if err == nil {
		return nil
	}

	// 已知需要重试的错误列表
	errs := []string{
		"closed by the remote host", "too many connections",
		"EOF", "A connection attempt failed",
		"established connection failed", "connection attempt failed",
		"Unable to read", "is not allowed to connect to this",
		"no pg_hba.conf entry",
		"No connection could be made",
		"invalid packet size",
		"bad connection",
	}

	// 检查错误是否匹配
	errLower := strings.ToLower(err.Error())
	for _, key := range errs {
		if strings.Contains(errLower, strings.ToLower(key)) {
			time.Sleep(3 * time.Second)
			return err
		}
	}

	return nil
}
