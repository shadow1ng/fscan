package i18n

import (
	"fmt"
	"sync"

	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
	"gopkg.in/yaml.v3"
)

// 支持的语言常量
const (
	LangZH = "zh"
	LangEN = "en"
)

// 默认配置
const (
	DefaultLanguage  = LangZH
	FallbackLanguage = LangEN
)

var (
	bundle    *i18n.Bundle
	localizer *i18n.Localizer
	lang      = DefaultLanguage
	mu        sync.RWMutex
)

func init() {
	bundle = i18n.NewBundle(language.Chinese)
	bundle.RegisterUnmarshalFunc("yaml", yaml.Unmarshal)

	// 从embed加载翻译文件
	if _, err := bundle.LoadMessageFileFS(localeFS, "locales/zh.yaml"); err != nil {
		panic(fmt.Sprintf("failed to load zh.yaml: %v", err))
	}
	if _, err := bundle.LoadMessageFileFS(localeFS, "locales/en.yaml"); err != nil {
		panic(fmt.Sprintf("failed to load en.yaml: %v", err))
	}

	localizer = i18n.NewLocalizer(bundle, lang, FallbackLanguage)
}

// SetLanguage 设置当前语言
func SetLanguage(l string) {
	mu.Lock()
	defer mu.Unlock()
	lang = l
	localizer = i18n.NewLocalizer(bundle, lang, FallbackLanguage)
}

// GetText 获取国际化文本（无参数）
func GetText(key string) string {
	mu.RLock()
	loc := localizer
	mu.RUnlock()

	msg, err := loc.Localize(&i18n.LocalizeConfig{
		MessageID: key,
	})
	if err != nil || msg == "" {
		return key
	}
	return msg
}

// Tr 获取国际化文本并格式化（变参版本）
// 参数按顺序映射为 {{.Arg1}}, {{.Arg2}}, ...
func Tr(key string, args ...interface{}) string {
	mu.RLock()
	loc := localizer
	mu.RUnlock()

	data := make(map[string]interface{})
	for i, arg := range args {
		data[fmt.Sprintf("Arg%d", i+1)] = arg
	}

	msg, err := loc.Localize(&i18n.LocalizeConfig{
		MessageID:    key,
		TemplateData: data,
	})
	if err != nil || msg == "" {
		return key
	}
	return msg
}
