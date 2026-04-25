# Fscan

[中文](README.md)

Comprehensive intranet scanning tool for automated vulnerability assessment.

**Version**: 2.1.1

## Features

### Scanning
- **Host Discovery** - ICMP/Ping alive detection, B/C segment statistics for large networks
- **Port Scanning** - TCP connect scan, 133 built-in ports, port groups (web/db/service/all)
- **Service Detection** - Smart protocol identification, 20+ service fingerprint matching
- **Web Detection** - Website title, CMS fingerprint, web middleware, WAF/CDN detection (40+ signatures)

### Brute Force
- **Password Cracking** - 28 services (SSH/RDP/SMB/FTP/MySQL/MSSQL/Oracle/Redis, etc.)
- **Hash Authentication** - NTLM Hash support (SMB/WMI)
- **SSH Key Login** - Private key authentication
- **Smart Dictionary** - 100+ common passwords, {user} variable substitution

### Vulnerability Detection
- **Critical Vulns** - MS17-010 (EternalBlue), SMBGhost (CVE-2020-0796)
- **Unauthorized Access** - Redis/MongoDB/Memcached/Elasticsearch unauthorized detection
- **POC Scanning** - Integrated web POC, Xray POC format support
- **DNSLog** - DNSLog out-of-band detection

### Exploitation
- **Redis Exploit** - Write pubkey, crontab, webshell, master-slave RCE
- **MS17-010 Exploit** - ShellCode injection, add user, execute commands
- **SSH Command Exec** - Auto command execution after authentication

### Local Modules
- **Info Gathering** - System info, environment variables, DC info, NIC config
- **Credential Access** - Memory dump (MiniDump), keylogger, registry export
- **Persistence** - Systemd service, Windows service, scheduled tasks, startup, LD_PRELOAD
- **Reverse Shell** - Forward shell, reverse shell, SOCKS5 proxy service
- **AV Detection** - Identify installed security software
- **Trace Cleanup** - Log cleaning tool

### Input/Output
- **Target Input** - IP/CIDR/domain/URL, batch file import
- **Exclusion Rules** - Exclude specific hosts, ports
- **Output Formats** - TXT/JSON/CSV multi-format output
- **Silent Mode** - No banner, no progress bar, no color output

### Network Control
- **Proxy Support** - HTTP/SOCKS5 proxy, network interface binding
- **Rate Control** - Rate limiting, max packet count control
- **Timeout Control** - Port/Web/Global timeout independent config
- **Concurrency** - Port scan threads, service scan threads independent config

### Extensions
- **Web Management UI** - Visual scan task management (build with -tags web)
- **Lab Environment** - Built-in Docker lab for testing and learning
- **Plugin Architecture** - Service/Web/Local plugins separated, easy to extend
- **Multi-language** - Chinese/English interface (-lang zh/en)
- **Performance Stats** - JSON format performance report (-perf)

## v2.1.0 Changelog

> This update includes **262 commits**: 30 new features, 120 fixes, 54 refactors, 14 performance optimizations, 20 test enhancements.

### Architecture Refactoring
- **Global Variable Elimination** - Migrated to Config/State objects for better concurrency safety and testability
- **SMB Plugin Consolidation** - Merged smb/smb2/smbghost/smbinfo into unified plugin with new smb_protocol.go
- **Service Probe Refactoring** - Implemented Nmap-style fallback mechanism, optimized port fingerprint strategy
- **Output System Refactoring** - TXT real-time flush + dual-write mechanism, resolved result loss and ordering issues
- **i18n Framework Upgrade** - Migrated to go-i18n, full coverage of core/plugins/webscan modules
- **HostInfo Refactoring** - Ports field changed from string to int for type safety
- **Function Complexity Optimization** - clusterpoc (125→30), EnhancedPortScan (111→20)
- **Code Audit** - Fixed P0-P2 level issues, cleaned up deadcode
- **Logging System Optimization** - LogDebug call cleanup (71→18), streamlined startup log output

### Performance Optimization
- **Regex Precompilation** - Global regex precompilation to avoid repeated compilation overhead
- **Memory Optimization** - Changed map[string]bool to map[string]struct{} for memory savings
- **Concurrent Fingerprint Matching** - Multi-goroutine parallel matching for faster identification
- **Connection Reuse** - SOCKS5 global dialer reuse to avoid repeated handshakes
- **Sliding Window Scheduling** - Adaptive thread pool + streaming iterator for port scan optimization
- **CEL Cache Optimization** - POC scan CEL environment caching to reduce repeated initialization
- **Package-level Variable Extraction** - proxyFailurePatterns/resourceExhaustedPatterns/sslSecondProbes etc.
- **Capacity Pre-allocation** - Simplified conversion chains, single-pass string replacement
- **Concurrency Safety Optimization** - Optimized lock granularity and memory allocation

### New Features
- **Web Management UI** - Visual scan task management with responsive layout and progress display
- **Multi-format POC Adapter** - Support for xray and afrog format POCs
- **Smart Scan Mode** - Bloom filter deduplication + proxy optimization
- **Enhanced Fingerprint Library** - Integrated FingerprintHub (3139 fingerprints)
- **Favicon Fingerprinting** - Support for mmh3 and MD5 dual-format hash matching
- **Universal Version Extractor** - Auto-extract service version information
- **Fingerprint Priority Sorting** - Smart sorting of match results
- **Smart Protocol Detection** - Auto-detect HTTP/HTTPS protocol type
- **Network Interface Binding** - Support for VPN scenarios (-iface parameter)
- **Exclude Hosts File** - Read excluded hosts from file (-ehf parameter)
- **ICMP Token Bucket Rate Limiting** - Prevent router crashes from high-speed scanning
- **Port Scan Retry** - Automatic retry mechanism for failed scans
- **RDP Real Authentication** - Integrated grdp library for system fingerprinting
- **SMB/FTP File Listing** - Auto-list files on anonymous access
- **302 Redirect Dual Detection** - Identify fingerprints from both original and redirected responses
- **TXT Output URL Summary** - Append web service URL list for batch testing
- **gonmap Core Integration** - Three improvements: probe strategy/matching engine/version parsing
- **Selective Plugin Compilation** - Build Tags system for independent service/local/web plugin compilation
- **Default Port Expansion** - Extended from 62 to 133 common ports
- **Full Port Scan Support** - Expanded port range limits
- **HTTP Redirect Control** - Configurable redirect count limit
- **Performance Profiling Support** - Added pprof profiling and benchmark tests
- **TCP Packet Statistics** - Service plugins support TCP packet send statistics
- **fscan-lab Environment** - Intranet penetration training platform covering all vulnerability scenarios
- **Redis Exploitation Enhancement** - Ported complete Redis exploitation (write pubkey/crontab/webshell/master-slave RCE)
- **rsync Plugin Refactoring** - Restructured authentication logic using go-rsync library

### Bug Fixes (120 items, key fixes listed)
- **RDP Null Pointer Panic** - Fixed certificate parsing crash (#551)
- **Batch Scan Missing Results** - Fixed large-scale scan omissions (#304)
- **JSON Output Format** - Fixed output format errors (#446)
- **Redis Weak Password Detection** - Fixed detection omissions (#447)
- **Real-time Result Saving** - Fixed scan results not saved timely (#469)
- **Nmap Parse Overflow** - Fixed octal escape parsing bug (#478)
- **Fingerprint Race Condition** - Fixed webtitle/webpoc race issues (#474)
- **MySQL Connection Validation** - Changed to information_schema for validation
- **Proxy Port Misjudgment** - Fixed port status judgment in proxy mode
- **Context Timeout** - Fixed 22 plugin timeout unresponsive issues
- **ICMP Race Condition** - Fixed concurrent scan race issues
- **IPv6 Address Format** - Fixed 4 address formatting issues
- **POC High Concurrency Hang** - Fixed Context propagation issues
- **Ctrl+C Result Loss** - Added signal handling for proper result saving
- **SOCKS5 Echo Issue** - Added proxy connection validation
- **Service Probe Leak** - Fixed connection not properly closed
- **webtitle Response Discard** - Fixed partial response data being discarded causing identification failure
- **TXT Vulnerability Info Missing** - Fixed output missing vulnerability details
- **JSON Fingerprint Missing** - Unified SERVICE result Target format
- **Scan Duration Display** - Fixed completion time showing as 0
- **False Vulnerability Records** - Refactored TXT output system to eliminate false positives
- **Redis Cross-platform Path** - Fixed exploitation path and timeout issues
- **Windows Compilation Warnings** - Fixed fscan-lite platform compatibility
- **Go 1.20 Compatibility** - Downgraded dependencies for compatibility

### Test Enhancements (20 items)
- **Unit Tests** - Core module coverage at 74-100%
- **Concurrency Safety Tests** - Dedicated tests for State object and fingerprint matching engine
- **Integration Tests** - Web scan/port scan/service probe/SSH auth/ICMP probe
- **CLI Parameter Tests** - Command-line argument parsing verification
- **Performance Benchmarks** - AdaptivePool and service probe strategy benchmarks
- **ResultBuffer Tests** - Deduplication and completeness scoring verification

### Engineering Improvements
- **CI Pipeline Optimization** - Upgraded to golangci-lint v2, simplified build steps
- **Issue Automation** - GitHub Issue template optimization, Project automation workflow
- **Full Lint Fixes** - revive/errcheck/shadow/staticcheck/gosimple all passing
- **README Rewrite** - Comprehensive Chinese and English documentation update
- **Code Format Unification** - gofmt/goimports standardization

## Quick Start

```bash
# Scan C-class network
./fscan -h 192.168.1.1/24

# Specify ports
./fscan -h 192.168.1.1 -p 22,80,443,3389

# Alive detection only
./fscan -h 192.168.1.1/24 -ao

# Disable brute force
./fscan -h 192.168.1.1/24 -nobr

# Web scanning
./fscan -u http://192.168.1.1

# Local plugin
./fscan -local systeminfo

# Hash authentication
./fscan -h 192.168.1.1 -m smb2 -user admin -hash xxxxx

# Redis write pubkey
./fscan -h 192.168.1.1 -m redis -rf id_rsa.pub
```

## Build

```bash
# Standard build
go build -ldflags="-s -w" -trimpath -o fscan main.go

# With Web UI
go build -tags web -ldflags="-s -w" -trimpath -o fscan main.go
```

## Install

```bash
# Arch Linux
yay -S fscan-git
```

## Screenshots

`fscan.exe -h 192.168.x.x`
![](image/1.png)

![](image/4.png)

`fscan.exe -h 192.168.x.x -rf id_rsa.pub` (Redis write pubkey)
![](image/2.png)

`fscan.exe -h 192.168.x.x -m ssh -user root -pwd password`
![](image/3.png)

`fscan.exe -h 192.168.x.x -p80 -proxy http://127.0.0.1:8080`
![](image/2020-12-12-13-34-44.png)

`fscan.exe -h 192.168.x.x -p 139 -m netbios`
![](image/netbios.png)

![](image/netbios1.png)

`fscan.exe -h 192.0.0.0/8 -m icmp`
![img.png](image/live.png)

![2.0-1](image/2.0-1.png)

![2.0-2](image/2.0-2.png)

## Roadmap

### Release Schedule
- **Release Cycle** - Monthly release
- **First 2 Weeks** - New features and enhancements
- **Last 2 Weeks** - Bug fixes and code integration
- **PRs Welcome** - Contributions are appreciated!

### Plugin Ecosystem
- Continuously expand service plugin coverage
- Develop more vulnerability detection and exploitation capabilities for each service plugin
- Maintain backward compatibility of plugin APIs to ensure legacy POCs remain functional

### Fscan-lite
- Lightweight version rewritten in C
- Smaller binary size, fewer dependencies
- Support for embedded/restricted environments
- Directory: [fscan-lite](./fscan-lite)

### Fscan-lab
- Intranet penetration testing lab environment
- Covers all vulnerability scenarios supported by fscan
- Development testing and feature verification platform
- Learning and practice environment for beginners
- Directory: [fscan-lab](./fscan-lab)

## Disclaimer

This tool is intended for **legally authorized** enterprise security testing only. Obtain proper authorization, comply with local laws, **do not scan unauthorized targets**. The author assumes no liability for any illegal use.

## 404StarLink

![](https://github.com/knownsec/404StarLink-Project/raw/master/logo.png)

fscan is a member of [404Team StarLink 2.0](https://github.com/knownsec/404StarLink2.0-Galaxy).

## Star History

[![Stargazers over time](https://starchart.cc/shadow1ng/fscan.svg)](https://starchart.cc/shadow1ng/fscan)

## Donate

[Buy the author a drink](image/sponsor.png)

## References

- https://github.com/Adminisme/ServerScan
- https://github.com/netxfly/x-crack
- https://github.com/hack2fun/Gscan
- https://github.com/k8gege/LadonGo
- https://github.com/jjf012/gopoc
- https://github.com/chainreactors/gogo
- https://github.com/0x727/FingerprintHub
- https://github.com/killmonday/fscanx
