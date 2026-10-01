//go:build !web

package main

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

func setPluginDefaultPorts(flags *common.FlagVars) {
	if flags.PortsExplicit || flags.PortsFile != "" || flags.AliveOnly || flags.LocalPlugin != "" {
		return
	}

	var ports []int
	for _, name := range strings.Split(flags.ScanMode, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		defaults := plugins.GetPluginPorts(name)
		// Web、本地插件和特殊模式没有固定端口，保留通用端口范围。
		if len(defaults) == 0 {
			return
		}
		ports = append(ports, defaults...)
	}
	if len(ports) > 0 {
		flags.Ports = formatPluginPorts(ports)
	}
}

func formatPluginPorts(ports []int) string {
	ports = slices.Clone(ports)
	slices.Sort(ports)
	var values []string
	for _, port := range slices.Compact(ports) {
		values = append(values, strconv.Itoa(port))
	}
	return strings.Join(values, ",")
}

func printPluginList(w io.Writer) error {
	names := plugins.All()
	slices.Sort(names)
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(table, i18n.GetText("plugin_list_header"))
	for _, name := range names {
		var types []string
		for _, kind := range []string{plugins.PluginTypeService, plugins.PluginTypeUDP, plugins.PluginTypeWeb, plugins.PluginTypeLocal} {
			if plugins.HasType(name, kind) {
				types = append(types, kind)
			}
		}
		ports := formatPluginPorts(plugins.GetPluginPorts(name))
		if ports == "" {
			ports = "-"
		}
		option := "-m"
		if plugins.HasType(name, plugins.PluginTypeLocal) {
			option = "-local"
		}
		_, _ = fmt.Fprintf(table, "%s\t%s\t%s\t%s %s\n", name, strings.Join(types, ","), ports, option, name)
	}
	return table.Flush()
}
