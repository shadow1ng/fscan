//go:build (plugin_systeminfo || !plugin_selective) && !windows && !no_local

package local

func (p *SystemInfoPlugin) collectDomainInfo() {}
