package core

import (
	"strings"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/parsers"
)

func loadHostExcludes(params *common.FlagVars) ([]string, error) {
	if params == nil {
		return nil, nil
	}

	excludes := make([]string, 0, 1)
	if strings.TrimSpace(params.ExcludeHosts) != "" {
		excludes = append(excludes, params.ExcludeHosts)
	}
	if strings.TrimSpace(params.ExcludeHostsFile) == "" {
		return excludes, nil
	}

	lines, err := parsers.ReadLinesFromFile(params.ExcludeHostsFile)
	if err != nil {
		return nil, err
	}
	return append(excludes, lines...), nil
}
