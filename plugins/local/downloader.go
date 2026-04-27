//go:build (plugin_downloader || !plugin_selective) && !no_local

package local

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// DownloaderPlugin 文件下载插件
// 设计哲学：直接实现，删除过度设计
// - 删除复杂的继承体系
// - 直接实现文件下载功能
// - 保持原有功能逻辑
type DownloaderPlugin struct {
	plugins.BasePlugin
}

// NewDownloaderPlugin 创建文件下载插件
func NewDownloaderPlugin() *DownloaderPlugin {
	return &DownloaderPlugin{
		BasePlugin: plugins.NewBasePlugin("downloader"),
	}
}

// Scan 执行文件下载任务 - 直接实现
func (p *DownloaderPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	config := session.Config
	var output strings.Builder

	// 从config获取配置
	downloadURL := config.LocalExploit.DownloadURL
	savePath := config.LocalExploit.DownloadSavePath
	downloadTimeout := 30 * time.Second
	maxFileSize := int64(100 * 1024 * 1024) // 100MB

	output.WriteString("=== 文件下载 ===\n")

	// 验证参数
	if err := p.validateParameters(downloadURL, &savePath); err != nil {
		output.WriteString(fmt.Sprintf("参数验证失败: %v\n", err))
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	output.WriteString(fmt.Sprintf("下载URL: %s\n", downloadURL))
	output.WriteString(fmt.Sprintf("保存路径: %s\n", savePath))
	output.WriteString(fmt.Sprintf("平台: %s\n\n", runtime.GOOS))

	// 检查保存路径权限
	if err := p.checkSavePathPermissions(&savePath); err != nil {
		output.WriteString(fmt.Sprintf("保存路径检查失败: %v\n", err))
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	// 执行下载
	downloadInfo, err := p.downloadFile(ctx, downloadURL, savePath, downloadTimeout, maxFileSize)
	if err != nil {
		output.WriteString(fmt.Sprintf("下载失败: %v\n", err))
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	// 输出下载结果
	output.WriteString("✓ 文件下载成功!\n")
	output.WriteString(fmt.Sprintf("文件大小: %v bytes\n", downloadInfo["file_size"]))
	if contentType, ok := downloadInfo["content_type"]; ok && contentType != "" {
		output.WriteString(fmt.Sprintf("文件类型: %v\n", contentType))
	}
	output.WriteString(fmt.Sprintf("下载用时: %v\n", downloadInfo["download_time"]))

	common.LogSuccess(i18n.Tr("downloader_success",
		downloadURL, savePath, downloadInfo["file_size"]))

	return &plugins.Result{
		Success: true,
		Type:    plugins.ResultTypeService,
		Output:  output.String(),
		Error:   nil,
	}
}

// validateParameters 验证输入参数
func (p *DownloaderPlugin) validateParameters(downloadURL string, savePath *string) error {
	if downloadURL == "" {
		return fmt.Errorf("下载URL不能为空，请使用 -download-url 参数指定")
	}

	// 验证URL格式
	if !strings.HasPrefix(strings.ToLower(downloadURL), "http://") &&
		!strings.HasPrefix(strings.ToLower(downloadURL), "https://") {
		return fmt.Errorf("无效的URL格式，必须以 http:// 或 https:// 开头")
	}

	// 如果没有指定保存路径，使用URL中的文件名
	if *savePath == "" {
		filename := p.extractFilenameFromURL(downloadURL)
		if filename == "" {
			filename = "downloaded_file"
		}
		*savePath = filename
	}

	return nil
}

// extractFilenameFromURL 从URL中提取文件名
func (p *DownloaderPlugin) extractFilenameFromURL(url string) string {
	// 移除查询参数
	if idx := strings.Index(url, "?"); idx != -1 {
		url = url[:idx]
	}

	// 获取路径的最后一部分
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		filename := parts[len(parts)-1]
		if filename != "" && !strings.Contains(filename, "=") {
			return filename
		}
	}

	return ""
}

// checkSavePathPermissions 检查保存路径权限
func (p *DownloaderPlugin) checkSavePathPermissions(savePath *string) error {
	// 获取保存目录
	saveDir := filepath.Dir(*savePath)
	if saveDir == "." || saveDir == "" {
		// 使用当前目录
		var err error
		saveDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("获取当前目录失败: %w", err)
		}
		*savePath = filepath.Join(saveDir, filepath.Base(*savePath))
	}

	// 确保目录存在
	if err := os.MkdirAll(saveDir, 0755); err != nil {
		return fmt.Errorf("创建保存目录失败: %w", err)
	}

	// 检查写入权限
	testFile := filepath.Join(saveDir, ".fscan_write_test")
	file, err := os.Create(testFile)
	if err != nil {
		return fmt.Errorf("保存目录无写入权限: %w", err)
	}
	_ = file.Close() // 测试文件，Close错误可忽略
	_ = os.Remove(testFile)

	return nil
}

// downloadFile 执行文件下载
func (p *DownloaderPlugin) downloadFile(ctx context.Context, downloadURL, savePath string, downloadTimeout time.Duration, maxFileSize int64) (map[string]interface{}, error) {
	startTime := time.Now()

	// 创建带超时的HTTP客户端
	client := &http.Client{
		Timeout: downloadTimeout,
	}

	// 创建请求
	req, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建HTTP请求失败: %w", err)
	}

	// 设置User-Agent
	req.Header.Set("User-Agent", "fscan-downloader/1.0")

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP请求失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() // HTTP响应体，Close错误可安全忽略

	// 检查HTTP状态码
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP请求失败，状态码: %d %s", resp.StatusCode, resp.Status)
	}

	// 检查文件大小
	contentLength := resp.ContentLength
	if contentLength > maxFileSize {
		return nil, fmt.Errorf("文件过大 (%d bytes)，超过最大限制 (%d bytes)",
			contentLength, maxFileSize)
	}

	// 创建保存文件
	outFile, err := os.Create(savePath)
	if err != nil {
		return nil, fmt.Errorf("创建保存文件失败: %w", err)
	}
	defer func() { _ = outFile.Close() }() // 文件资源清理，Close错误可安全忽略

	// 使用带限制的Reader防止过大文件
	limitedReader := io.LimitReader(resp.Body, maxFileSize)

	// 复制数据
	written, err := io.Copy(outFile, limitedReader)
	if err != nil {
		// 清理部分下载的文件
		_ = os.Remove(savePath) // 清理临时文件，Remove错误可忽略
		return nil, fmt.Errorf("文件下载失败: %w", err)
	}

	downloadTime := time.Since(startTime)

	// 返回下载信息
	downloadInfo := map[string]interface{}{
		"save_path":     savePath,
		"file_size":     written,
		"content_type":  resp.Header.Get("Content-Type"),
		"download_time": downloadTime,
	}

	return downloadInfo, nil
}

// 注册插件
func init() {
	RegisterLocalPlugin("downloader", func() Plugin {
		return NewDownloaderPlugin()
	})
}
