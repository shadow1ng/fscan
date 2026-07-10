package common

import (
	"net/url"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/shadow1ng/fscan/common/parsers"
)

const maxAutoOutputNameRunes = 120

func resolveDefaultOutputFile(fv *FlagVars, info *HostInfo) {
	if fv == nil {
		return
	}
	if fv.OutputFileExplicit || (fv.Outputfile != "" && fv.Outputfile != "result.txt") {
		return
	}

	extension := outputExtension(fv.OutputFormat)
	target := firstOutputTarget(fv, info)
	name := sanitizeOutputTarget(target)
	if name == "" {
		name = "result"
	}
	fv.Outputfile = name + "." + extension
}

func outputExtension(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		return "json"
	case "csv":
		return "csv"
	default:
		return "txt"
	}
}

func firstOutputTarget(fv *FlagVars, info *HostInfo) string {
	if info != nil {
		if target := firstCommaValue(info.Host); target != "" {
			return target
		}
	}
	if target := firstCommaValue(fv.TargetURL); target != "" {
		return target
	}
	if target := firstTargetFromFile(fv.HostsFile); target != "" {
		return target
	}
	if target := firstTargetFromFile(fv.URLsFile); target != "" {
		return target
	}
	if info != nil {
		return strings.TrimSpace(info.URL)
	}
	return ""
}

func firstCommaValue(input string) string {
	for _, value := range strings.Split(input, ",") {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func firstTargetFromFile(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	lines, err := parsers.ReadLinesFromFile(path)
	if err != nil {
		return ""
	}
	for _, line := range lines {
		if target := firstCommaValue(line); target != "" {
			return target
		}
	}
	return ""
}

func sanitizeOutputTarget(target string) string {
	target = strings.TrimSpace(target)
	if parsed, err := url.Parse(target); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		target = parsed.Host
	}

	var builder strings.Builder
	lastUnderscore := false
	for _, r := range target {
		invalid := unicode.IsControl(r) || strings.ContainsRune(`<>:"/\|?*`, r)
		if invalid {
			if !lastUnderscore {
				builder.WriteByte('_')
				lastUnderscore = true
			}
			continue
		}
		builder.WriteRune(r)
		lastUnderscore = false
	}
	name := strings.Trim(builder.String(), " ._")
	name = truncateOutputName(name, maxAutoOutputNameRunes)
	if isReservedWindowsName(name) {
		name = "_" + name
	}
	return name
}

func truncateOutputName(name string, maxRunes int) string {
	if utf8.RuneCountInString(name) <= maxRunes {
		return name
	}
	runes := []rune(name)
	return string(runes[:maxRunes])
}

func isReservedWindowsName(name string) bool {
	base := strings.ToUpper(strings.TrimSuffix(name, filepath.Ext(name)))
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CLOCK$":
		return true
	}
	for _, prefix := range []string{"COM", "LPT"} {
		if strings.HasPrefix(base, prefix) && len(base) == 4 && base[3] >= '1' && base[3] <= '9' {
			return true
		}
	}
	return false
}
