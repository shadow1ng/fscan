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
	status = &ScanStatus{lastSuccess: time.Now(), lastError: time.Now()}

	// 扫描计数
	Num int64 // 总任务数
	End int64 // 已完成任务数

	// 文件写入器
	fileWriter *bufferedFileWriter
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

// JsonOutput JSON输出的结构体
type JsonOutput struct {
	Level     string    `json:"level"`
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message"`
}

func InitLogger() {
	log.SetOutput(io.Discard)
	if !DisableSave {
		fileWriter = newBufferedFileWriter()
	}
}

// formatLogMessage 格式化日志消息
func formatLogMessage(entry *LogEntry) string {
	timeStr := entry.Time.Format("2006-01-02 15:04:05")
	return fmt.Sprintf("[%s] [%s] %s", timeStr, entry.Level, entry.Content)
}

// 修改 printLog 函数
func printLog(entry *LogEntry) {
	if LogLevel != LogLevelAll &&
		entry.Level != LogLevel &&
		!(LogLevel == LogLevelInfo && (entry.Level == LogLevelInfo || entry.Level == LogLevelSuccess)) {
		return
	}

	OutputMutex.Lock()
	defer OutputMutex.Unlock()

	// 确保清除当前进度条
	if ProgressBar != nil {
		ProgressBar.Clear()
		time.Sleep(10 * time.Millisecond)
	}

	// 打印日志
	logMsg := formatLogMessage(entry)
	if !NoColor {
		if colorAttr, ok := logColors[entry.Level]; ok {
			color.New(colorAttr).Println(logMsg)
		} else {
			fmt.Println(logMsg)
		}
	} else {
		fmt.Println(logMsg)
	}

	// 确保日志完全输出
	time.Sleep(50 * time.Millisecond)

	// 重新渲染进度条
	if ProgressBar != nil {
		ProgressBar.RenderBlank()
	}
}

func LogError(errMsg string) {
	_, file, line, ok := runtime.Caller(1)
	if !ok {
		file = "unknown"
		line = 0
	}
	file = filepath.Base(file)

	errorMsg := fmt.Sprintf("%s:%d - %s", file, line, errMsg)

	if ProgressBar != nil {
		ProgressBar.Clear()
	}

	entry := &LogEntry{
		Level:   LogLevelError,
		Time:    time.Now(),
		Content: errorMsg,
	}

	printLog(entry)
	if fileWriter != nil {
		fileWriter.write(entry)
	}

	if ProgressBar != nil {
		ProgressBar.RenderBlank()
	}
}

func LogInfo(msg string) {
	if ProgressBar != nil {
		ProgressBar.Clear()
	}

	entry := &LogEntry{
		Level:   LogLevelInfo,
		Time:    time.Now(),
		Content: msg,
	}

	printLog(entry)
	if fileWriter != nil {
		fileWriter.write(entry)
	}

	if ProgressBar != nil {
		ProgressBar.RenderBlank()
	}
}

func LogSuccess(result string) {
	if ProgressBar != nil {
		ProgressBar.Clear()
	}

	entry := &LogEntry{
		Level:   LogLevelSuccess,
		Time:    time.Now(),
		Content: result,
	}

	printLog(entry)
	if fileWriter != nil {
		fileWriter.write(entry)
	}

	status.mu.Lock()
	status.lastSuccess = time.Now()
	status.mu.Unlock()

	if ProgressBar != nil {
		ProgressBar.RenderBlank()
	}
}

func newBufferedFileWriter() *bufferedFileWriter {
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

type bufferedFileWriter struct {
	file    *os.File
	writer  *bufio.Writer
	jsonEnc *json.Encoder
	mu      sync.Mutex // 添加互斥锁保护写入
}

func (w *bufferedFileWriter) write(entry *LogEntry) {
	if w == nil {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	var err error
	if JsonFormat {
		output := JsonOutput{
			Level:     entry.Level,
			Timestamp: entry.Time,
			Message:   entry.Content,
		}
		err = w.jsonEnc.Encode(output)
	} else {
		logMsg := formatLogMessage(entry) + "\n"
		_, err = w.writer.WriteString(logMsg)
	}

	if err != nil {
		fmt.Printf("[ERROR] 写入日志失败: %v\n", err)
		// 尝试重新打开文件
		if err := w.reopen(); err != nil {
			fmt.Printf("[ERROR] 重新打开文件失败: %v\n", err)
			return
		}
		return
	}

	// 每隔一定数量的写入才进行一次Flush
	if err := w.writer.Flush(); err != nil {
		fmt.Printf("[ERROR] 刷新缓冲区失败: %v\n", err)
		if err := w.reopen(); err != nil {
			fmt.Printf("[ERROR] 重新打开文件失败: %v\n", err)
		}
	}
}

func (w *bufferedFileWriter) reopen() error {
	if w.file != nil {
		w.file.Close()
	}

	file, err := os.OpenFile(Outputfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return err
	}

	w.file = file
	w.writer = bufio.NewWriter(file)
	w.jsonEnc = json.NewEncoder(w.writer)
	return nil
}

func (w *bufferedFileWriter) close() {
	if w != nil {
		w.writer.Flush()
		w.file.Close()
	}
}

func CloseLogger() {
	if fileWriter != nil {
		fileWriter.close()
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
