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
	LogDebug(GetText("output_init_start"))

	// 验证输出格式
	switch OutputFormat {
	case "txt", "json", "csv":
		// 有效的格式
	default:
		return fmt.Errorf(GetText("output_format_invalid"), OutputFormat)
	}

	// 验证输出路径
	if Outputfile == "" {
		return fmt.Errorf(GetText("output_path_empty"))
	}

	dir := filepath.Dir(Outputfile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		LogDebug(GetText("output_create_dir_failed", err))
		return fmt.Errorf(GetText("output_create_dir_failed", err))
	}

	manager := &OutputManager{
		outputPath:   Outputfile,
		outputFormat: OutputFormat,
	}

	if err := manager.initialize(); err != nil {
		LogDebug(GetText("output_init_failed", err))
		return fmt.Errorf(GetText("output_init_failed", err))
	}

	ResultOutput = manager
	LogDebug(GetText("output_init_success"))
	return nil
}

func (om *OutputManager) initialize() error {
	om.mu.Lock()
	defer om.mu.Unlock()

	if om.isInitialized {
		LogDebug(GetText("output_already_init"))
		return nil
	}

	LogDebug(GetText("output_opening_file", om.outputPath))
	file, err := os.OpenFile(om.outputPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		LogDebug(GetText("output_open_file_failed", err))
		return fmt.Errorf(GetText("output_open_file_failed", err))
	}
	om.file = file

	switch om.outputFormat {
	case "csv":
		LogDebug(GetText("output_init_csv"))
		om.csvWriter = csv.NewWriter(file)
		headers := []string{"Time", "Type", "Target", "Status", "Details"}
		if err := om.csvWriter.Write(headers); err != nil {
			LogDebug(GetText("output_write_csv_header_failed", err))
			file.Close()
			return fmt.Errorf(GetText("output_write_csv_header_failed", err))
		}
		om.csvWriter.Flush()
	case "json":
		LogDebug(GetText("output_init_json"))
		om.jsonEncoder = json.NewEncoder(file)
		om.jsonEncoder.SetIndent("", "  ")
	case "txt":
		LogDebug(GetText("output_init_txt"))
	default:
		LogDebug(GetText("output_format_invalid", om.outputFormat))
	}

	om.isInitialized = true
	LogDebug(GetText("output_init_complete"))
	return nil
}

// SaveResult 保存扫描结果
func SaveResult(result *ScanResult) error {
	if ResultOutput == nil {
		LogDebug(GetText("output_not_init"))
		return fmt.Errorf(GetText("output_not_init"))
	}

	LogDebug(GetText("output_saving_result", result.Type, result.Target))
	return ResultOutput.saveResult(result)
}

func (om *OutputManager) saveResult(result *ScanResult) error {
	om.mu.Lock()
	defer om.mu.Unlock()

	if !om.isInitialized {
		LogDebug(GetText("output_not_init"))
		return fmt.Errorf(GetText("output_not_init"))
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
		LogDebug(GetText("output_format_invalid", om.outputFormat))
		return fmt.Errorf(GetText("output_format_invalid", om.outputFormat))
	}

	if err != nil {
		LogDebug(GetText("output_save_failed", err))
	} else {
		LogDebug(GetText("output_save_success", result.Type, result.Target))
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

	txt := GetText("output_txt_format",
		result.Time.Format("2006-01-02 15:04:05"),
		result.Type,
		result.Target,
		result.Status,
		details,
	) + "\n"
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
		LogDebug(GetText("output_no_need_close"))
		return nil
	}

	LogDebug(GetText("output_closing"))
	ResultOutput.mu.Lock()
	defer ResultOutput.mu.Unlock()

	if !ResultOutput.isInitialized {
		LogDebug(GetText("output_no_need_close"))
		return nil
	}

	if ResultOutput.csvWriter != nil {
		LogDebug(GetText("output_flush_csv"))
		ResultOutput.csvWriter.Flush()
	}

	if err := ResultOutput.file.Close(); err != nil {
		LogDebug(GetText("output_close_failed", err))
		return fmt.Errorf(GetText("output_close_failed", err))
	}

	ResultOutput.isInitialized = false
	LogDebug(GetText("output_closed"))
	return nil
}
