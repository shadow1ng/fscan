# Fscan

[English](README_EN.md)

内网综合扫描工具，一键自动化漏扫。

**版本**: 2.1.1

## 功能特性

### 扫描能力
- **主机发现** - ICMP/Ping存活探测，支持大网段B/C段存活统计
- **端口扫描** - TCP全连接扫描，内置133个常用端口，支持端口组(web/db/service/all)
- **服务识别** - 智能协议识别，支持20+种服务指纹匹配
- **Web探测** - 网站标题、CMS指纹、Web中间件、WAF/CDN识别(40+指纹)

### 爆破能力
- **弱密码爆破** - 28种服务爆破(SSH/RDP/SMB/FTP/MySQL/MSSQL/Oracle/Redis等)
- **Hash碰撞** - 支持NTLM Hash认证(SMB/WMI)
- **SSH密钥登录** - 支持私钥认证方式
- **智能字典** - 内置100+常见弱密码，支持{user}变量替换

### 漏洞检测
- **高危漏洞** - MS17-010(永恒之蓝)、SMBGhost(CVE-2020-0796)
- **未授权访问** - Redis/MongoDB/Memcached/Elasticsearch等未授权检测
- **POC扫描** - 集成Web漏洞POC，支持Xray POC格式
- **DNSLog** - 支持DNSLog外带检测

### 漏洞利用
- **Redis利用** - 写公钥、写计划任务、写WebShell、主从复制RCE
- **MS17-010利用** - ShellCode注入，支持添加用户、执行命令
- **SSH命令执行** - 认证成功后自动执行命令

### 本地模块
- **信息收集** - 系统信息、环境变量、域控信息、网卡配置
- **凭据获取** - 内存转储(MiniDump)、键盘记录、注册表导出
- **权限维持** - Systemd服务、Windows服务、计划任务、启动项、LD_PRELOAD
- **反弹Shell** - 正向Shell、反向Shell、SOCKS5代理服务
- **杀软检测** - 识别目标主机安装的安全软件
- **痕迹清理** - 日志清理工具

### 输入输出
- **目标输入** - IP/CIDR/域名/URL，支持文件批量导入
- **排除规则** - 支持排除特定主机、端口
- **输出格式** - TXT/JSON/CSV多格式输出
- **静默模式** - 无Banner、无进度条、无颜色输出

### 网络控制
- **代理支持** - HTTP/SOCKS5代理，支持指定网卡
- **发包控制** - 速率限制、最大发包数量控制
- **超时控制** - 端口超时、Web超时、全局超时独立配置
- **并发控制** - 端口扫描线程、服务扫描线程独立配置

### 扩展功能
- **Web管理界面** - 可视化扫描任务管理(条件编译 -tags web)
- **Lab靶场环境** - 内置Docker靶场用于测试学习
- **插件化架构** - 服务插件/Web插件/本地插件分离，易于扩展
- **多语言支持** - 中英文界面切换(-lang zh/en)
- **性能统计** - JSON格式性能报告(-perf)

## v2.1.0 更新日志

> 本次更新包含 **262个提交**，涵盖30项新功能、120项修复、54项重构、14项性能优化、20项测试增强。

### 架构重构
- **全局变量消除** - 迁移至Config/State对象，提升并发安全和可测试性
- **SMB插件融合** - 整合smb/smb2/smbghost/smbinfo为统一插件，新增smb_protocol.go
- **服务探测重构** - 实现Nmap风格fallback机制，优化端口指纹识别策略
- **输出系统重构** - TXT实时刷盘+双写机制，解决结果丢失和乱序问题
- **i18n框架升级** - 迁移至go-i18n，完整覆盖core/plugins/webscan模块
- **HostInfo重构** - Ports字段从string改为int，类型安全
- **函数复杂度优化** - clusterpoc(125→30)、EnhancedPortScan(111→20)
- **代码审计** - 修复P0-P2级别问题，清理deadcode
- **日志系统优化** - LogDebug调用清理(71→18)，精简启动日志输出

### 性能优化
- **正则预编译** - 全局正则表达式预编译，避免重复编译开销
- **内存优化** - map[string]bool改为map[string]struct{}节省内存
- **并发指纹匹配** - 多协程并行匹配，提升识别速度
- **连接复用** - SOCKS5全局拨号器复用，避免重复握手
- **滑动窗口调度** - 自适应线程池+流式迭代器，优化端口扫描
- **CEL缓存优化** - POC扫描CEL环境缓存，减少重复初始化
- **包级变量提取** - proxyFailurePatterns/resourceExhaustedPatterns/sslSecondProbes等
- **预分配容量** - 简化转换链、单次字符串替换
- **并发安全优化** - 优化锁粒度和内存分配

### 新功能
- **Web管理界面** - 可视化扫描任务管理，响应式布局和进度显示
- **多格式POC适配** - 支持xray和afrog格式POC
- **智能扫描模式** - 布隆过滤器去重+代理优化
- **增强指纹库** - 集成FingerprintHub(3139条指纹)
- **Favicon指纹识别** - 支持mmh3和MD5双格式hash匹配
- **通用版本提取器** - 自动提取服务版本信息
- **指纹优先级排序** - 智能排序匹配结果
- **智能协议检测** - 自动识别HTTP/HTTPS协议类型
- **网卡指定功能** - 支持VPN场景(-iface参数)
- **排除主机文件** - 支持从文件读取排除主机(-ehf参数)
- **ICMP令牌桶限速** - 防止高速扫描导致路由器崩溃
- **端口扫描重试** - 失败自动重扫机制
- **RDP真实认证** - 集成grdp库实现系统指纹识别
- **SMB/FTP文件列表** - 匿名访问时自动列出文件
- **302跳转双重识别** - 同时识别原始响应和跳转后响应指纹
- **TXT输出URL汇总** - 末尾添加Web服务URL列表便于批量测试
- **nmap核心集成** - 三大改进：探测策略/匹配引擎/版本解析
- **插件选择性编译** - Build Tags系统，支持服务/本地/Web插件独立编译
- **默认端口扩展** - 从62个扩展到133个常用端口
- **全端口扫描支持** - 扩大端口范围限制
- **HTTP重定向控制** - 可配置的重定向次数限制
- **性能分析支持** - 添加pprof性能分析和benchmark测试
- **TCP包统计** - 服务插件支持TCP包发送统计
- **fscan-lab靶场** - 内网渗透训练平台，覆盖全部漏洞场景（未完成）
- **Redis利用增强** - 移植完整Redis利用功能(写公钥/计划任务/WebShell/主从RCE)
- **rsync插件重构** - 使用go-rsync库重构认证逻辑

### Bug修复（120项，列出关键修复）
- **RDP空指针panic** - 修复证书解析导致的崩溃(#551)
- **批量扫描漏报** - 修复大规模扫描遗漏问题(#304)
- **JSON输出格式** - 修复输出格式错误(#446)
- **Redis弱密码检测** - 修复检测遗漏问题(#447)
- **结果实时保存** - 修复扫描结果未及时保存(#469)
- **Nmap解析溢出** - 修复八进制转义解析bug(#478)
- **指纹识别竞态** - 修复webtitle/webpoc竞态问题(#474)
- **MySQL连接验证** - 改用information_schema库验证
- **代理端口误判** - 修复代理模式下端口状态判断错误
- **Context超时** - 修复22处插件超时未响应问题
- **ICMP竞态条件** - 修复并发扫描竞争问题
- **IPv6地址格式** - 修复4处地址格式化问题
- **POC高并发卡死** - 修复Context未传播问题
- **Ctrl+C结果丢失** - 添加信号处理确保结果写入
- **SOCKS5全回显** - 添加代理连接验证
- **服务探测泄漏** - 修复连接未正确关闭问题
- **webtitle响应丢弃** - 修复部分响应数据被丢弃导致识别失败
- **TXT漏洞信息缺失** - 修复输出遗漏漏洞详情
- **JSON指纹缺失** - 统一SERVICE结果Target格式
- **扫描耗时显示** - 修复完成耗时显示为0的问题
- **虚假漏洞记录** - 重构TXT输出系统消除误报
- **Redis跨平台路径** - 修复利用功能的路径和超时问题
- **Windows编译警告** - 修复fscan-lite平台兼容性
- **Go 1.20兼容** - 降级依赖保持兼容性

### 测试增强（20项）
- **单元测试** - 核心模块覆盖率74-100%
- **并发安全测试** - State对象、指纹匹配引擎专项测试
- **集成测试** - Web扫描/端口扫描/服务探测/SSH认证/ICMP探测
- **CLI参数测试** - 命令行参数解析验证
- **性能基准测试** - AdaptivePool、服务探测策略benchmark
- **ResultBuffer测试** - 去重和完整度评分验证

### 工程化改进
- **CI流程优化** - golangci-lint v2升级，简化构建步骤
- **Issue自动化** - GitHub Issue模板优化，Project自动化工作流
- **Lint全量修复** - revive/errcheck/shadow/staticcheck/gosimple全部通过
- **README重写** - 中英文文档全面更新
- **代码格式统一** - gofmt/goimports规范化

## 快速开始

```bash
# 扫描C段
./fscan -h 192.168.1.1/24

# 指定端口
./fscan -h 192.168.1.1 -p 22,80,443,3389

# 仅存活探测
./fscan -h 192.168.1.1/24 -ao

# 禁用爆破
./fscan -h 192.168.1.1/24 -nobr

# Web扫描
./fscan -u http://192.168.1.1

# 本地插件
./fscan -local systeminfo

# Hash碰撞
./fscan -h 192.168.1.1 -m smb2 -user admin -hash xxxxx

# Redis写公钥
./fscan -h 192.168.1.1 -m redis -rf id_rsa.pub
```

## 编译

```bash
# 标准编译
go build -ldflags="-s -w" -trimpath -o fscan main.go

# 带Web管理界面
go build -tags web -ldflags="-s -w" -trimpath -o fscan main.go
```

## 安装

```bash
# Arch Linux
yay -S fscan-git
```

## 运行截图

`fscan.exe -h 192.168.x.x`
![](image/1.png)

![](image/4.png)

`fscan.exe -h 192.168.x.x -rf id_rsa.pub` (Redis写公钥)
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

## 路线图

### 更新计划
- **更新周期** - 每月一次版本发布
- **前两周** - 新功能开发与特性更新
- **后两周** - Bug修复与代码整合
- **欢迎PR** - 期待您的贡献！

### 插件生态
- 持续扩展服务插件覆盖范围
- 为每个服务插件开发更多漏洞检测和利用能力
- 保持插件API向后兼容，确保旧版本POC持续可用

### Fscan-lite
- C语言重写的轻量版本
- 更小的体积，更少的依赖
- 支持更多嵌入式/受限环境
- 目录: [fscan-lite](./fscan-lite)

### Fscan-lab
- 内网渗透测试靶场环境
- 覆盖所有fscan支持的漏洞场景
- 开发测试与功能验证平台
- 新手学习与技能练习环境
- 目录: [fscan-lab](./fscan-lab)

## 免责声明

本工具仅面向**合法授权**的企业安全建设行为。使用前请确保已获得授权，符合当地法律法规，**不对非授权目标扫描**。作者不承担任何非法使用产生的后果。

## 404StarLink

![](https://github.com/knownsec/404StarLink-Project/raw/master/logo.png)

fscan 是 [404Team 星链计划2.0](https://github.com/knownsec/404StarLink2.0-Galaxy) 成员项目。

## Star趋势

[![Stargazers over time](https://starchart.cc/shadow1ng/fscan.svg)](https://starchart.cc/shadow1ng/fscan)

## 捐赠

[请作者喝饮料](image/sponsor.png)

## 参考

- https://github.com/Adminisme/ServerScan
- https://github.com/netxfly/x-crack
- https://github.com/hack2fun/Gscan
- https://github.com/k8gege/LadonGo
- https://github.com/jjf012/gopoc
- https://github.com/chainreactors/gogo
- https://github.com/0x727/FingerprintHub
- https://github.com/killmonday/fscanx
