package common

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/shadow1ng/fscan/common/config"
	"github.com/shadow1ng/fscan/common/parsers"
)

/*
config_builder.go - 统一配置构建入口

从 FlagVars 直接构建 Config 和 State，消除中间层。
*/

// BuildConfig 从 FlagVars 构建完整的 Config 和 State
// 这是新的统一入口，替代原来的 Parse() + BuildConfigFromFlags() + updateGlobalVariables()
func BuildConfig(fv *FlagVars, info *HostInfo) (*Config, *State, error) {
	// 1. 构建基础 Config（从 flag_config.go 的 BuildConfigFromFlags）
	cfg := BuildConfigFromFlags(fv)

	// 2. 创建 State
	state := NewState()

	// 3. 解析凭据
	if err := parseCredentials(fv, cfg); err != nil {
		return nil, nil, fmt.Errorf("凭据解析失败: %w", err)
	}

	// 4. 解析目标（主机、端口、URL）
	if err := parseTargets(fv, info, cfg, state); err != nil {
		return nil, nil, fmt.Errorf("目标解析失败: %w", err)
	}

	// 5. 应用日志级别
	applyLogLevelFromConfig(fv)

	return cfg, state, nil
}

// =============================================================================
// 凭据解析
// =============================================================================

func parseCredentials(fv *FlagVars, cfg *Config) error {
	// 解析用户名
	usernames := parseUsernames(fv)
	if len(usernames) > 0 {
		for serviceName := range cfg.Credentials.Userdict {
			cfg.Credentials.Userdict[serviceName] = usernames
		}
	}

	// 解析密码
	passwords := parsePasswords(fv)
	if len(passwords) > 0 {
		cfg.Credentials.Passwords = passwords
	}

	// 解析用户密码对
	pairs, err := parseUserPassPairs(fv)
	if err != nil {
		return err
	}
	if len(pairs) > 0 {
		cfg.Credentials.UserPassPairs = pairs
	}

	// 解析哈希
	hashValues, hashBytes, err := parseHashes(fv)
	if err != nil {
		return err
	}
	if len(hashValues) > 0 {
		cfg.Credentials.HashValues = hashValues
		cfg.Credentials.HashBytes = hashBytes
	}

	return nil
}

func parseUsernames(fv *FlagVars) []string {
	var usernames []string

	// 命令行用户名
	if fv.Username != "" {
		for _, u := range strings.Split(fv.Username, ",") {
			u = strings.TrimSpace(u)
			if u != "" {
				usernames = append(usernames, u)
			}
		}
	}

	// 从文件读取
	if fv.UsersFile != "" {
		if lines, err := parsers.ReadLinesFromFile(fv.UsersFile); err == nil {
			usernames = append(usernames, lines...)
		} else {
			LogError(fmt.Sprintf("读取用户名文件 %s 失败: %v", fv.UsersFile, err))
		}
	}

	// 额外用户名
	if fv.AddUsers != "" {
		for _, u := range strings.Split(fv.AddUsers, ",") {
			u = strings.TrimSpace(u)
			if u != "" {
				usernames = append(usernames, u)
			}
		}
	}

	return removeDuplicate(usernames)
}

func parsePasswords(fv *FlagVars) []string {
	var passwords []string

	// 命令行密码
	if fv.Password != "" {
		passwords = append(passwords, strings.Split(fv.Password, ",")...)
	}

	// 从文件读取
	if fv.PasswordsFile != "" {
		if lines, err := parsers.ReadLinesFromFile(fv.PasswordsFile); err == nil {
			passwords = append(passwords, lines...)
		} else {
			LogError(fmt.Sprintf("读取密码文件 %s 失败: %v", fv.PasswordsFile, err))
		}
	}

	// 额外密码
	if fv.AddPasswords != "" {
		passwords = append(passwords, strings.Split(fv.AddPasswords, ",")...)
	}

	return removeDuplicate(passwords)
}

func parseUserPassPairs(fv *FlagVars) ([]config.CredentialPair, error) {
	var pairs []config.CredentialPair

	// 如果命令行同时指定了单个用户名和单个密码（不是逗号分隔的多个）
	if fv.Username != "" && fv.Password != "" &&
		!strings.Contains(fv.Username, ",") && !strings.Contains(fv.Password, ",") &&
		fv.UsersFile == "" && fv.PasswordsFile == "" && fv.UserPassFile == "" {
		pairs = append(pairs, config.CredentialPair{
			Username: strings.TrimSpace(fv.Username),
			Password: fv.Password,
		})
		return pairs, nil
	}

	// 从文件读取用户密码对
	if fv.UserPassFile != "" {
		filePairs, err := parsers.ParseUserPassFile(fv.UserPassFile)
		if err != nil {
			return nil, err
		}
		pairs = append(pairs, filePairs...)
	}

	return pairs, nil
}

func parseHashes(fv *FlagVars) ([]string, [][]byte, error) {
	var hashValues []string
	var hashBytes [][]byte

	// 命令行哈希
	if fv.HashValue != "" {
		hash := strings.TrimSpace(fv.HashValue)
		if len(hash) == 32 {
			hashValues = append(hashValues, hash)
			if hashByte, err := hex.DecodeString(hash); err == nil {
				hashBytes = append(hashBytes, hashByte)
			}
		}
	}

	// 从文件读取
	if fv.HashFile != "" {
		fileHashes, fileHashBytes, err := parsers.ParseHashFile(fv.HashFile)
		if err != nil {
			return nil, nil, err
		}
		hashValues = append(hashValues, fileHashes...)
		hashBytes = append(hashBytes, fileHashBytes...)
	}

	return hashValues, hashBytes, nil
}

// =============================================================================
// 目标解析
// =============================================================================

func parseTargets(fv *FlagVars, info *HostInfo, cfg *Config, state *State) error {
	// 检查是否为 host:port 格式
	ports := fv.Ports
	if info.Host != "" && strings.Contains(info.Host, ":") {
		if _, portStr, err := net.SplitHostPort(info.Host); err == nil {
			if port, portErr := strconv.Atoi(portStr); portErr == nil && port >= 1 && port <= 65535 {
				// 有效的 host:port 格式
				state.SetHostPorts([]string{info.Host})
				ports = "" // 清空端口，避免双重扫描
			}
		}
	}

	// 解析 URL
	urls := parseURLs(fv)
	if len(urls) > 0 {
		state.SetURLs(urls)
		if info.URL == "" && len(urls) == 1 {
			info.URL = urls[0]
		}
	}

	// 更新端口配置
	if ports != "" {
		cfg.Target.Ports = ports
	}

	return nil
}

func parseURLs(fv *FlagVars) []string {
	var urls []string

	// 命令行 URL
	if fv.TargetURL != "" {
		for _, u := range strings.Split(fv.TargetURL, ",") {
			u = strings.TrimSpace(u)
			if u != "" {
				urls = append(urls, normalizeURL(u))
			}
		}
	}

	// 从文件读取
	if fv.URLsFile != "" {
		if lines, err := parsers.ReadLinesFromFile(fv.URLsFile); err == nil {
			for _, line := range lines {
				urls = append(urls, normalizeURL(line))
			}
		} else {
			LogError(fmt.Sprintf("读取URL文件 %s 失败: %v", fv.URLsFile, err))
		}
	}

	return removeDuplicate(urls)
}

func normalizeURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return rawURL
	}
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return "http://" + rawURL
	}
	return rawURL
}

// =============================================================================
// 日志级别应用
// =============================================================================

func applyLogLevelFromConfig(fv *FlagVars) {
	if fv.LogLevel == "" {
		return
	}
	// 调用已有的 applyLogLevel 函数
	applyLogLevel()
}

// =============================================================================
// 辅助函数
// =============================================================================

func removeDuplicate(old []string) []string {
	if len(old) <= 1 {
		return old
	}

	temp := make(map[string]struct{}, len(old))
	result := make([]string, 0, len(old))

	for _, item := range old {
		if _, exists := temp[item]; !exists {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}

	return result
}

// =============================================================================
// 保留 BuildConfigFromFlags 的原有实现（从 flag_config.go 移入）
// =============================================================================

// BuildConfigFromFlags 已在 flag_config.go 中定义，这里不重复
