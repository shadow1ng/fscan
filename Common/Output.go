// output.go

package Common

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// 全局输出管理器
var ResultOutput *OutputManager

// OutputManager 输出管理器结构体
type OutputManager struct {
	mu            sync.Mutex
	outputPath    string
	outputFormat  string
	file          *os.File
	csvWriter     *csv.Writer
	jsonEncoder   *json.Encoder
	isInitialized bool
}

// ResultType 定义结果类型
type ResultType string

const (
	HOST    ResultType = "HOST"    // 主机存活
	PORT    ResultType = "PORT"    // 端口开放
	SERVICE ResultType = "SERVICE" // 服务识别
	VULN    ResultType = "VULN"    // 漏洞发现
)

// ScanResult 扫描结果结构
type ScanResult struct {
	Time    time.Time              `json:"time"`    // 发现时间
	Type    ResultType             `json:"type"`    // 结果类型
	Target  string                 `json:"target"`  // 目标(IP/域名/URL)
	Status  string                 `json:"status"`  // 状态描述
	Details map[string]interface{} `json:"details"` // 详细信息
}

// InitOutput 初始化输出系统
func InitOutput() error {
	LogDebug("开始初始化输出系统")

	// 验证输出格式
	switch OutputFormat {
	case "txt", "json", "csv":
		// 有效的格式
	default:
		return fmt.Errorf("不支持的输出格式: %s", OutputFormat)
	}

	// 验证输出路径
	if Outputfile == "" {
		return fmt.Errorf("输出文件路径不能为空")
	}

	dir := filepath.Dir(Outputfile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		LogDebug(fmt.Sprintf("创建输出目录失败: %v", err))
		return fmt.Errorf("创建输出目录失败: %v", err)
	}

	manager := &OutputManager{
		outputPath:   Outputfile,
		outputFormat: OutputFormat,
	}

	if err := manager.initialize(); err != nil {
		LogDebug(fmt.Sprintf("初始化输出管理器失败: %v", err))
		return fmt.Errorf("初始化输出管理器失败: %v", err)
	}

	ResultOutput = manager
	LogDebug("输出系统初始化完成")
	return nil
}

func (om *OutputManager) initialize() error {
	om.mu.Lock()
	defer om.mu.Unlock()

	if om.isInitialized {
		LogDebug("输出管理器已经初始化，跳过")
		return nil
	}

	LogDebug(fmt.Sprintf("正在打开输出文件: %s", om.outputPath))
	file, err := os.OpenFile(om.outputPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		LogDebug(fmt.Sprintf("打开输出文件失败: %v", err))
		return fmt.Errorf("打开输出文件失败: %v", err)
	}
	om.file = file

	switch om.outputFormat {
	case "csv":
		LogDebug("初始化CSV写入器")
		om.csvWriter = csv.NewWriter(file)
		headers := []string{"Time", "Type", "Target", "Status", "Details"}
		if err := om.csvWriter.Write(headers); err != nil {
			LogDebug(fmt.Sprintf("写入CSV头失败: %v", err))
			file.Close()
			return fmt.Errorf("写入CSV头失败: %v", err)
		}
		om.csvWriter.Flush()
	case "json":
		LogDebug("初始化JSON编码器")
		om.jsonEncoder = json.NewEncoder(file)
		om.jsonEncoder.SetIndent("", "  ")
	case "txt":
		LogDebug("初始化文本输出")
	default:
		LogDebug(fmt.Sprintf("不支持的输出格式: %s", om.outputFormat))
	}

	om.isInitialized = true
	LogDebug("输出管理器初始化完成")
	return nil
}

// SaveResult 保存扫描结果
func SaveResult(result *ScanResult) error {
	if ResultOutput == nil {
		LogDebug("输出系统未初始化")
		return fmt.Errorf("输出系统未初始化")
	}

	LogDebug(fmt.Sprintf("正在保存结果 - 类型: %s, 目标: %s", result.Type, result.Target))
	return ResultOutput.saveResult(result)
}

func (om *OutputManager) saveResult(result *ScanResult) error {
	om.mu.Lock()
	defer om.mu.Unlock()

	if !om.isInitialized {
		LogDebug("输出管理器未初始化")
		return fmt.Errorf("输出管理器未初始化")
	}

	var err error
	switch om.outputFormat {
	case "txt":
		err = om.writeTxt(result)
	case "json":
		err = om.writeJson(result)
	case "csv":
		err = om.writeCsv(result)
	default:
		LogDebug(fmt.Sprintf("不支持的输出格式: %s", om.outputFormat))
		return fmt.Errorf("不支持的输出格式: %s", om.outputFormat)
	}

	if err != nil {
		LogDebug(fmt.Sprintf("保存结果失败: %v", err))
	} else {
		LogDebug(fmt.Sprintf("成功保存结果 - 类型: %s, 目标: %s", result.Type, result.Target))
	}
	return err
}

func (om *OutputManager) writeTxt(result *ScanResult) error {
	// 格式化 Details 为键值对字符串
	var details string
	if len(result.Details) > 0 {
		pairs := make([]string, 0, len(result.Details))
		for k, v := range result.Details {
			pairs = append(pairs, fmt.Sprintf("%s=%v", k, v))
		}
		details = strings.Join(pairs, ", ")
	}

	txt := fmt.Sprintf("[%s] [%s] Target: %s, Status: %s, Details: {%s}\n",
		result.Time.Format("2006-01-02 15:04:05"),
		result.Type,
		result.Target,
		result.Status,
		details,
	)
	_, err := om.file.WriteString(txt)
	return err
}

func (om *OutputManager) writeJson(result *ScanResult) error {
	return om.jsonEncoder.Encode(result)
}

func (om *OutputManager) writeCsv(result *ScanResult) error {
	details, err := json.Marshal(result.Details)
	if err != nil {
		details = []byte("{}")
	}

	record := []string{
		result.Time.Format("2006-01-02 15:04:05"),
		string(result.Type),
		result.Target,
		result.Status,
		string(details),
	}

	if err := om.csvWriter.Write(record); err != nil {
		return err
	}
	om.csvWriter.Flush()
	return om.csvWriter.Error()
}

// CloseOutput 关闭输出系统
func CloseOutput() error {
	if ResultOutput == nil {
		LogDebug("输出系统未初始化，无需关闭")
		return nil
	}

	LogDebug("正在关闭输出系统")
	ResultOutput.mu.Lock()
	defer ResultOutput.mu.Unlock()

	if !ResultOutput.isInitialized {
		LogDebug("输出管理器未初始化，无需关闭")
		return nil
	}

	if ResultOutput.csvWriter != nil {
		LogDebug("刷新CSV写入器缓冲区")
		ResultOutput.csvWriter.Flush()
	}

	if err := ResultOutput.file.Close(); err != nil {
		LogDebug(fmt.Sprintf("关闭文件失败: %v", err))
		return fmt.Errorf("关闭文件失败: %v", err)
	}

	ResultOutput.isInitialized = false
	LogDebug("输出系统已关闭")
	return nil
}
