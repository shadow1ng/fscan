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
	outputPath    string        // 输出文件路径
	outputFormat  string        // 输出格式(txt/json/csv)
	file          *os.File      // 文件句柄
	csvWriter     *csv.Writer   // CSV写入器
	jsonEncoder   *json.Encoder // JSON编码器
	isInitialized bool          // 是否已初始化
}

// ResultType 定义结果类型的枚举
type ResultType string

// 结果类型常量
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

// InitOutput 初始化输出系统，创建文件并设置相应格式的写入器
func InitOutput() error {
	LogDebug(GetText("output_init_start"))

	// 验证输出格式
	if OutputFormat != "txt" && OutputFormat != "json" && OutputFormat != "csv" {
		return fmt.Errorf(GetText("output_format_invalid"), OutputFormat)
	}

	// 验证并创建输出路径
	if Outputfile == "" {
		return fmt.Errorf(GetText("output_path_empty"))
	}

	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(Outputfile), 0755); err != nil {
		LogDebug(GetText("output_create_dir_failed", err))
		return err
	}

	// API模式下特殊处理
	if ApiAddr != "" {
		OutputFormat = "csv"
		Outputfile = filepath.Join(filepath.Dir(Outputfile), "fscanapi.csv")
		Num, End = 0, 0
		// 删除已存在的文件
		if _, err := os.Stat(Outputfile); err == nil {
			os.Remove(Outputfile)
		}
	}

	// 创建管理器
	ResultOutput = &OutputManager{
		outputPath:   Outputfile,
		outputFormat: OutputFormat,
	}

	// 创建并打开文件
	file, err := os.OpenFile(Outputfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		LogDebug(GetText("output_open_file_failed", err))
		return err
	}
	ResultOutput.file = file

	// 根据格式初始化相应的写入器
	switch OutputFormat {
	case "csv":
		ResultOutput.csvWriter = csv.NewWriter(file)
		// 写入CSV头部
		if err := ResultOutput.csvWriter.Write([]string{"Time", "Type", "Target", "Status", "Details"}); err != nil {
			file.Close()
			return err
		}
		ResultOutput.csvWriter.Flush()

	case "json":
		ResultOutput.jsonEncoder = json.NewEncoder(file)
		ResultOutput.jsonEncoder.SetIndent("", "  ")
	}

	ResultOutput.isInitialized = true
	LogDebug(GetText("output_init_success"))
	return nil
}

// SaveResult 保存扫描结果到文件
func SaveResult(result *ScanResult) error {
	// 验证输出管理器是否初始化
	if ResultOutput == nil || !ResultOutput.isInitialized {
		LogDebug(GetText("output_not_init"))
		return fmt.Errorf(GetText("output_not_init"))
	}

	LogDebug(GetText("output_saving_result", result.Type, result.Target))

	ResultOutput.mu.Lock()
	defer ResultOutput.mu.Unlock()

	var err error

	// 根据不同格式写入结果
	switch ResultOutput.outputFormat {
	case "txt":
		// 格式化详情为键值对字符串
		var details string
		if len(result.Details) > 0 {
			pairs := make([]string, 0, len(result.Details))
			for k, v := range result.Details {
				pairs = append(pairs, fmt.Sprintf("%s=%v", k, v))
			}
			details = strings.Join(pairs, ", ")
		}

		// 写入文本格式
		txt := GetText("output_txt_format",
			result.Time.Format("2006-01-02 15:04:05"),
			result.Type,
			result.Target,
			result.Status,
			details,
		) + "\n"
		_, err = ResultOutput.file.WriteString(txt)

	case "json":
		// 写入JSON格式
		err = ResultOutput.jsonEncoder.Encode(result)

	case "csv":
		// 将详情序列化为JSON字符串
		details, jsonErr := json.Marshal(result.Details)
		if jsonErr != nil {
			details = []byte("{}")
		}

		// 写入CSV记录
		record := []string{
			result.Time.Format("2006-01-02 15:04:05"),
			string(result.Type),
			result.Target,
			result.Status,
			string(details),
		}

		if err = ResultOutput.csvWriter.Write(record); err == nil {
			ResultOutput.csvWriter.Flush()
			err = ResultOutput.csvWriter.Error()
		}
	}

	if err != nil {
		LogDebug(GetText("output_save_failed", err))
	} else {
		LogDebug(GetText("output_save_success", result.Type, result.Target))
	}
	return err
}

// GetResults 从CSV文件中读取已保存的结果
func GetResults() ([]*ScanResult, error) {
	// 验证输出管理器是否初始化且为CSV格式
	if ResultOutput == nil || !ResultOutput.isInitialized {
		return nil, fmt.Errorf(GetText("output_not_init"))
	}

	if ResultOutput.outputFormat != "csv" {
		return nil, fmt.Errorf(GetText("output_format_read_not_supported"))
	}

	ResultOutput.mu.Lock()
	defer ResultOutput.mu.Unlock()

	// 打开文件进行读取
	file, err := os.Open(ResultOutput.outputPath)
	if err != nil {
		LogDebug(GetText("output_open_file_failed", err))
		return nil, err
	}
	defer file.Close()

	// 读取CSV记录
	records, err := csv.NewReader(file).ReadAll()
	if err != nil {
		LogDebug(GetText("output_read_csv_failed", err))
		return nil, err
	}

	// 解析记录到结构体
	var results []*ScanResult
	for i, row := range records {
		// 跳过CSV头部和不完整记录
		if i == 0 || len(row) < 5 {
			continue
		}

		// 解析时间
		t, err := time.Parse("2006-01-02 15:04:05", row[0])
		if err != nil {
			continue
		}

		// 解析详情JSON
		var details map[string]interface{}
		if err := json.Unmarshal([]byte(row[4]), &details); err != nil {
			details = make(map[string]interface{})
		}

		// 创建结果对象
		results = append(results, &ScanResult{
			Time:    t,
			Type:    ResultType(row[1]),
			Target:  row[2],
			Status:  row[3],
			Details: details,
		})
	}

	LogDebug(GetText("output_read_csv_success", len(results)))
	return results, nil
}

// CloseOutput 关闭输出系统
func CloseOutput() error {
	// 验证是否需要关闭
	if ResultOutput == nil || !ResultOutput.isInitialized {
		LogDebug(GetText("output_no_need_close"))
		return nil
	}

	LogDebug(GetText("output_closing"))

	ResultOutput.mu.Lock()
	defer ResultOutput.mu.Unlock()

	// CSV格式需要刷新缓冲
	if ResultOutput.csvWriter != nil {
		ResultOutput.csvWriter.Flush()
	}

	// 关闭文件
	err := ResultOutput.file.Close()
	if err != nil {
		LogDebug(GetText("output_close_failed", err))
		return err
	}

	ResultOutput.isInitialized = false
	LogDebug(GetText("output_closed"))
	return nil
}
