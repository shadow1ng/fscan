package common

/*
output_api.go - 输出系统简化接口

提供扫描结果输出的统一API，底层使用output包实现。
*/

import (
	"fmt"

	"github.com/shadow1ng/fscan/common/output"
)

// ResultOutput 全局输出管理器
var ResultOutput *output.Manager

// StdoutWriter silent模式下的NDJSON stdout写入器
var StdoutWriter *output.StdoutNDJSONWriter

// InitOutput 初始化输出系统
func InitOutput() error {
	fv := GetFlagVars()

	// silent模式：初始化NDJSON stdout写入器（独立于文件输出）
	if fv.Silent {
		StdoutWriter = output.NewStdoutNDJSONWriter()
	}

	// 用户通过-no flag禁用保存时，跳过文件初始化避免不必要的资源开销
	if fv.DisableSave {
		return nil
	}

	outputFile := fv.Outputfile
	outputFormat := fv.OutputFormat

	if outputFile == "" {
		return fmt.Errorf("output file not specified")
	}

	var format output.Format
	switch outputFormat {
	case "txt":
		format = output.FormatTXT
	case "json":
		format = output.FormatJSON
	case "csv":
		format = output.FormatCSV
	default:
		return fmt.Errorf("invalid output format: %s", outputFormat)
	}

	// 如果使用默认文件名但格式不是txt，自动修正扩展名
	if outputFile == "result.txt" && outputFormat != "txt" {
		outputFile = "result." + outputFormat
	}

	config := output.DefaultManagerConfig(outputFile, format)
	manager, err := output.NewManager(config)
	if err != nil {
		return err
	}
	ResultOutput = manager
	return nil
}

// CloseOutput 关闭输出系统
func CloseOutput() error {
	if StdoutWriter != nil {
		_ = StdoutWriter.Close()
	}
	if ResultOutput == nil {
		return nil
	}
	return ResultOutput.Close()
}

// SaveResult 保存扫描结果
func SaveResult(result *output.ScanResult) error {
	if result == nil {
		return nil
	}

	// 通知Web（无论是否保存文件）
	NotifyResult(map[string]interface{}{
		"type":    string(result.Type),
		"target":  result.Target,
		"status":  result.Status,
		"time":    result.Time,
		"details": result.Details,
	})

	// silent模式：NDJSON实时输出到stdout
	if StdoutWriter != nil {
		_ = StdoutWriter.WriteResult(result)
	}

	// 用户禁用保存或输出未初始化时，跳过文件保存
	if GetGlobalConfig().Output.DisableSave || ResultOutput == nil {
		return nil
	}
	return ResultOutput.SaveResult(result)
}
