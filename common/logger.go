package common

/*
logger.go - 日志系统简化接口

提供统一的日志API，底层使用logging包实现。
*/

import (
	"strings"
	"sync"

	"github.com/shadow1ng/fscan/common/logging"
)

var (
	globalLogger *logging.Logger
	loggerOnce   sync.Once
)

func getGlobalLogger() *logging.Logger {
	loggerOnce.Do(func() {
		fv := GetFlagVars()
		level := getLogLevelFromString(fv.LogLevel)
		config := &logging.LoggerConfig{
			Level:        level,
			EnableColor:  !fv.NoColor,
			SlowOutput:   false,
			ShowProgress: !fv.DisableProgress,
			Silent:       fv.Silent,
			StartTime:    GetGlobalState().GetStartTime(),
		}
		if fv.Debug {
			config.DebugLogFile = "fscan_debug.log"
		}
		globalLogger = logging.NewLogger(config)
		globalLogger.SetCoordinatedOutput(LogWithProgress)
	})
	return globalLogger
}

func getLogLevelFromString(levelStr string) logging.LogLevel {
	switch strings.ToLower(levelStr) {
	case "all":
		return logging.LevelAll
	case "error":
		return logging.LevelError
	case "base":
		return logging.LevelBase
	case "info":
		return logging.LevelInfo
	case "success":
		return logging.LevelSuccess
	case "debug":
		return logging.LevelDebug
	case "info,success":
		return logging.LevelInfoSuccess
	case "base,info,success", "base_info_success":
		return logging.LevelBaseInfoSuccess
	default:
		return logging.LevelInfoSuccess
	}
}

// InitLogger 初始化日志系统
func InitLogger() {
	getGlobalLogger().Initialize()
}

// LogDebug 输出调试日志
func LogDebug(msg string) { getGlobalLogger().Debug(msg) }

// LogInfo 输出信息日志
func LogInfo(msg string) { getGlobalLogger().Info(msg) }

// LogSuccess 输出成功日志（Web指纹等）
func LogSuccess(result string) { getGlobalLogger().Success(result) }

// LogVuln 输出漏洞/重要发现日志（密码成功、漏洞等）
func LogVuln(result string) { getGlobalLogger().Vuln(result) }

// LogError 输出错误日志
func LogError(errMsg string) { getGlobalLogger().Error(errMsg) }

// CloseLogger 关闭日志系统，释放文件资源
func CloseLogger() {
	if globalLogger != nil {
		globalLogger.Close()
	}
}
