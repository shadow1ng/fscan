//go:build (plugin_fileinfo || !plugin_selective) && !no_local

package local

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// FileInfoPlugin 文件信息收集插件
// 设计哲学：删除所有不必要的复杂性
// - 没有继承体系
// - 没有权限检查（让系统告诉我们）
// - 没有平台检查（运行时错误更清晰）
// - 没有复杂配置（直接硬编码关键路径）
type FileInfoPlugin struct {
	plugins.BasePlugin
}

// NewFileInfoPlugin 创建文件信息插件
func NewFileInfoPlugin() *FileInfoPlugin {
	return &FileInfoPlugin{
		BasePlugin: plugins.NewBasePlugin("fileinfo"),
	}
}

// Scan 执行本地文件扫描 - 直接、简单、有效
func (p *FileInfoPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	var foundFiles []string

	// 扫描关键敏感文件位置 - 删除复杂的配置系统
	sensitiveFiles := p.getSensitiveFiles()
	for _, file := range sensitiveFiles {
		if p.fileExists(file) {
			foundFiles = append(foundFiles, file)
			common.LogSuccess(i18n.Tr("fileinfo_sensitive", file))
		}
	}

	// 搜索用户目录下的敏感文件 - 简化搜索逻辑
	userFiles := p.searchUserFiles()
	foundFiles = append(foundFiles, userFiles...)

	// 构建结果
	output := fmt.Sprintf("文件扫描完成 - 发现 %d 个敏感文件", len(foundFiles))
	if len(foundFiles) > 0 {
		output += "\n发现的文件:"
		for _, file := range foundFiles {
			output += "\n  " + file
		}
	}

	return &plugins.Result{
		Success: len(foundFiles) > 0,
		Output:  output,
		Error:   nil,
	}
}

// getSensitiveFiles 获取关键敏感文件列表 - 删除复杂的初始化逻辑
func (p *FileInfoPlugin) getSensitiveFiles() []string {
	var files []string

	switch runtime.GOOS {
	case "windows":
		files = []string{
			"C:\\boot.ini",
			"C:\\Windows\\System32\\config\\SAM",
			"C:\\Windows\\repair\\sam",
		}

		// 添加用户相关路径
		if homeDir, err := os.UserHomeDir(); err == nil {
			files = append(files, []string{
				filepath.Join(homeDir, ".ssh", "id_rsa"),
				filepath.Join(homeDir, ".aws", "credentials"),
				filepath.Join(homeDir, ".azure", "accessTokens.json"),
			}...)
		}

	case "linux", "darwin":
		files = []string{
			"/etc/passwd",
			"/etc/shadow",
			"/root/.ssh/id_rsa",
			"/root/.ssh/authorized_keys",
			"/root/.bash_history",
			"/etc/nginx/nginx.conf",
			"/etc/apache2/apache2.conf",
		}

		// 添加用户相关路径
		if homeDir, err := os.UserHomeDir(); err == nil {
			files = append(files, []string{
				filepath.Join(homeDir, ".ssh", "id_rsa"),
				filepath.Join(homeDir, ".aws", "credentials"),
				filepath.Join(homeDir, ".bash_history"),
			}...)
		}
	}

	return files
}

// searchUserFiles 搜索用户目录敏感文件 - 简化搜索逻辑
func (p *FileInfoPlugin) searchUserFiles() []string {
	var foundFiles []string

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return foundFiles
	}

	// 关键目录 - 删除复杂的目录配置
	searchDirs := []string{
		filepath.Join(homeDir, "Desktop"),
		filepath.Join(homeDir, "Documents"),
		filepath.Join(homeDir, ".ssh"),
		filepath.Join(homeDir, ".aws"),
	}

	// 敏感文件关键词 - 删除复杂的白名单系统
	keywords := []string{"password", "key", "secret", "token", "credential", "passwd"}

	for _, dir := range searchDirs {
		if !p.dirExists(dir) {
			continue
		}

		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			// 限制深度和大小 - 简单有效
			if info.IsDir() || info.Size() > 1024*1024 { // 1MB
				return nil
			}

			// 检查文件名是否包含敏感关键词
			filename := strings.ToLower(filepath.Base(path))
			for _, keyword := range keywords {
				if strings.Contains(filename, keyword) {
					foundFiles = append(foundFiles, path)
					common.LogSuccess(i18n.Tr("fileinfo_potential", path))
					break
				}
			}

			return nil
		})
	}

	return foundFiles
}

// fileExists 检查文件是否存在
func (p *FileInfoPlugin) fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// dirExists 检查目录是否存在
func (p *FileInfoPlugin) dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// 注册插件
func init() {
	RegisterLocalPlugin("fileinfo", func() Plugin {
		return NewFileInfoPlugin()
	})
}
