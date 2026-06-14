package common

import (
	"github.com/shadow1ng/fscan/common/logging"
)

// logLevelMap 日志级别字符串到级别的映射
var logLevelMap = map[string]logging.LogLevel{
	LogLevelAll:             logging.LevelAll,
	LogLevelError:           logging.LevelError,
	LogLevelBase:            logging.LevelBase,
	LogLevelInfo:            logging.LevelInfo,
	LogLevelSuccess:         logging.LevelSuccess,
	LogLevelDebug:           logging.LevelDebug,
	LogLevelInfoSuccess:     logging.LevelInfoSuccess,
	LogLevelBaseInfoSuccess: logging.LevelBaseInfoSuccess,
	// 旧格式（大写，向后兼容）
	"ALL":     logging.LevelAll,
	"ERROR":   logging.LevelError,
	"BASE":    logging.LevelBase,
	"INFO":    logging.LevelInfo,
	"SUCCESS": logging.LevelSuccess,
	"DEBUG":   logging.LevelDebug,
}

// applyLogLevel 应用LogLevel配置到日志系统
func applyLogLevel() {
	fv := GetFlagVars()
	logLevel := fv.LogLevel
	if logLevel == "" {
		return
	}

	level, ok := logLevelMap[logLevel]
	if !ok {
		return
	}

	if globalLogger != nil {
		config := &logging.LoggerConfig{
			Level:        level,
			EnableColor:  !fv.NoColor,
			SlowOutput:   false,
			ShowProgress: !fv.DisableProgress,
			StartTime:    GetGlobalState().GetStartTime(),
			LevelColors:  logging.GetDefaultLevelColors(),
		}
		if fv.Debug {
			config.DebugLogFile = "fscan_debug.log"
		}

		newLogger := logging.NewLogger(config)
		newLogger.SetCoordinatedOutput(LogWithProgress)
		globalLogger = newLogger
	}
}
