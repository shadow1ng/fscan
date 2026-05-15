//go:build (plugin_cleaner || !plugin_selective) && !windows && !no_local

package local

import "strings"

func cleanPersistence(output *strings.Builder) int {
	return 0
}
