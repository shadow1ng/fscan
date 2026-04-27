//go:build (plugin_envinfo || !plugin_selective) && !no_local

package local

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// EnvInfoPlugin 环境变量信息收集插件
// 设计哲学："做一件事并做好"
// - 专注于环境变量收集
// - 过滤敏感信息关键词
// - 简单有效的实现
type EnvInfoPlugin struct {
	plugins.BasePlugin
}

// NewEnvInfoPlugin 创建环境变量信息插件
func NewEnvInfoPlugin() *EnvInfoPlugin {
	return &EnvInfoPlugin{
		BasePlugin: plugins.NewBasePlugin("envinfo"),
	}
}

// Scan 执行环境变量收集 - 直接、有效
func (p *EnvInfoPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	var output strings.Builder
	var sensitiveVars []string

	output.WriteString("=== 环境变量信息收集 ===\n")

	// 获取所有环境变量
	envs := os.Environ()
	output.WriteString(fmt.Sprintf("总环境变量数: %d\n\n", len(envs)))

	// 敏感关键词 - 直接硬编码，简单有效
	sensitiveKeywords := []string{
		"password", "passwd", "pwd", "secret", "key", "token",
		"auth", "credential", "api", "access", "session",
		"密码", "令牌", "密钥", "认证",
	}

	// 重要环境变量 - 系统相关
	importantVars := []string{
		"PATH", "HOME", "USER", "USERNAME", "USERPROFILE", "TEMP", "TMP",
		"HOMEPATH", "COMPUTERNAME", "USERDOMAIN", "PROCESSOR_ARCHITECTURE",
	}

	output.WriteString("=== 重要环境变量 ===\n")
	for _, envVar := range importantVars {
		if value := os.Getenv(envVar); value != "" {
			// PATH特殊处理 - 只显示条目数
			if envVar == "PATH" {
				paths := strings.Split(value, string(os.PathListSeparator))
				output.WriteString(fmt.Sprintf("%s: %d个路径\n", envVar, len(paths)))
			} else {
				output.WriteString(fmt.Sprintf("%s: %s\n", envVar, value))
			}
		}
	}

	// 扫描所有环境变量寻找敏感信息
	output.WriteString("\n=== 潜在敏感环境变量 ===\n")
	for _, env := range envs {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}

		envName := strings.ToLower(parts[0])
		envValue := parts[1]

		// 检查是否包含敏感关键词
		for _, keyword := range sensitiveKeywords {
			if strings.Contains(envName, keyword) {
				// 脱敏显示：只显示前几个字符
				displayValue := envValue
				if len(envValue) > 10 {
					displayValue = envValue[:10] + "..."
				}

				sensitiveInfo := fmt.Sprintf("%s: %s", parts[0], displayValue)
				sensitiveVars = append(sensitiveVars, sensitiveInfo)
				output.WriteString(sensitiveInfo + "\n")
				common.LogSuccess(i18n.Tr("envinfo_sensitive", parts[0]))
				break
			}
		}
	}

	if len(sensitiveVars) == 0 {
		output.WriteString("未发现明显的敏感环境变量\n")
	}

	// 统计信息
	output.WriteString("\n=== 统计结果 ===\n")
	output.WriteString(fmt.Sprintf("总环境变量: %d个\n", len(envs)))
	output.WriteString(fmt.Sprintf("潜在敏感变量: %d个\n", len(sensitiveVars)))

	// 按长度统计
	shortVars, longVars := 0, 0
	for _, env := range envs {
		if len(env) < 50 {
			shortVars++
		} else {
			longVars++
		}
	}
	output.WriteString(fmt.Sprintf("短变量(<50字符): %d个\n", shortVars))
	output.WriteString(fmt.Sprintf("长变量(≥50字符): %d个\n", longVars))

	return &plugins.Result{
		Success: len(sensitiveVars) > 0,
		Output:  output.String(),
		Error:   nil,
	}
}

// 注册插件
func init() {
	RegisterLocalPlugin("envinfo", func() Plugin {
		return NewEnvInfoPlugin()
	})
}
