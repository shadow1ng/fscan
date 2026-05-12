---
name: fscan-agent
description: 使用 fscan 进行网络扫描和安全评估。当用户要求扫描网段、探测主机存活、发现开放端口、识别服务、检测漏洞或弱口令时使用。支持 NDJSON 结构化输出，适合 AI agent 管道消费。
argument-hint: <目标IP/网段> [附加参数]
allowed-tools: Bash, Read, Agent
---

# Fscan AI Agent Skill

## 工具概述

Fscan 是一款内网综合扫描工具，功能包括：
- 主机存活探测（ICMP / TCP）
- 端口扫描与服务识别
- 漏洞检测（MS17-010、Redis 未授权等）
- 弱口令爆破（SSH、SMB、MySQL、MSSQL、FTP、RDP 等）
- Web 指纹识别与 POC 扫描
- NetBIOS / SMB 信息收集
- 本地信息收集（杀软检测、系统信息等）

二进制路径：当前项目编译产物 `fscan_cli`，或系统 PATH 中的 `fscan`。

## 调用格式

```bash
# AI agent 标准用法：NDJSON 输出，无人类日志干扰
fscan -h <目标> -silent [其他参数]

# 解析输出
fscan -h 192.168.1.0/24 -silent | jq 'select(.type=="VULN")'
```

## 核心参数

### 目标指定

| 参数 | 说明 | 示例 |
|------|------|------|
| `-h` | 目标主机（IP / CIDR / 范围） | `-h 192.168.1.0/24` `-h 10.0.0.1-10.0.0.100` |
| `-hf` | 从文件读取目标 | `-hf targets.txt` |
| `-p` | 指定端口（逗号/范围） | `-p 22,80,443,445,3306` `-p 1-1000` |
| `-ep` | 排除端口 | `-ep 25,110` |
| `-eh` | 排除主机 | `-eh 192.168.1.1` |
| `-u` | 指定 URL（Web 扫描） | `-u https://example.com` |
| `-uf` | URL 文件 | `-uf urls.txt` |

### 扫描控制

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-m` | 扫描模式 | `all` |
| `-t` | 端口扫描线程数 | `600` |
| `-mt` | 模块线程数 | `20` |
| `-time` | 连接超时（秒） | `3` |
| `-gt` | 全局超时（秒） | `180` |
| `-np` | 跳过存活检测 | `false` |
| `-ntp` | 禁用 TCP 补充探测 | `false` |
| `-ao` | 仅存活检测 | `false` |
| `-nobr` | 禁用暴力破解 | `false` |
| `-full` | 全量 POC 扫描 | `false` |
| `-max-retries` | 最大重试次数 | `1` |

### 认证

| 参数 | 说明 |
|------|------|
| `-user` | 用户名 |
| `-pwd` | 密码 |
| `-usera` | 追加用户名 |
| `-pwda` | 追加密码 |
| `-userf` | 用户名字典文件 |
| `-pwdf` | 密码字典文件 |
| `-domain` | 域名（SMB/WMI） |
| `-sshkey` | SSH 私钥文件 |
| `-hash` / `-hashf` | NTLM Hash / Hash 文件 |

### 代理

| 参数 | 说明 |
|------|------|
| `-socks5` | SOCKS5 代理 (`127.0.0.1:1080`) |
| `-proxy` | HTTP 代理 (`http://127.0.0.1:8080`) |
| `-iface` | 指定本地网卡 IP（VPN 场景） |

### 输出

| 参数 | 说明 |
|------|------|
| `-silent` | 静默模式：stdout 仅输出 NDJSON |
| `-o` | 输出文件路径（默认 `result.txt`） |
| `-f` | 输出格式：`txt` / `json` / `csv` |
| `-no` | 禁用文件保存 |
| `-debug` | 调试模式：日志写入 `fscan_debug.log` |
| `-log` | 日志级别（`debug` / `info` / `base` / `error`） |

### 扫描模式 `-m` 的取值

| 值 | 说明 |
|------|------|
| `all` | 全部扫描（默认） |
| `icmp` | 仅 ICMP 存活检测 |
| 插件名 | 仅运行指定插件（如 `ssh`、`smb`、`ms17010`、`webtitle`） |

## 服务插件列表

| 插件 | 默认端口 | 功能 |
|------|----------|------|
| `ftp` | 21 | FTP 弱口令 |
| `ssh` | 22 | SSH 弱口令 |
| `telnet` | 23 | Telnet 弱口令 |
| `smtp` | 25 | SMTP 弱口令 |
| `findnet` | 135 | RPC 网络信息发现（NetInfo） |
| `netbios` | 139 | NetBIOS 信息收集 |
| `smb` | 445 | SMB 弱口令 |
| `ms17010` | 445 | MS17-010 永恒之蓝检测 |
| `ldap` | 389 | LDAP 弱口令 |
| `mssql` | 1433 | MSSQL 弱口令 |
| `oracle` | 1521 | Oracle 弱口令 |
| `mysql` | 3306 | MySQL 弱口令 |
| `rdp` | 3389 | RDP 弱口令 + 系统信息 |
| `postgresql` | 5432 | PostgreSQL 弱口令 |
| `vnc` | 5900 | VNC 弱口令 |
| `redis` | 6379 | Redis 未授权 + 弱口令 |
| `elasticsearch` | 9200 | ES 未授权 |
| `mongodb` | 27017 | MongoDB 未授权 + 弱口令 |
| `memcached` | 11211 | Memcached 未授权 |
| `kafka` | 9092 | Kafka 未授权 |
| `activemq` | 61616 | ActiveMQ 弱口令 |
| `rabbitmq` | 5672 | RabbitMQ 弱口令 |
| `cassandra` | 9042 | Cassandra 弱口令 |
| `neo4j` | 7687 | Neo4j 弱口令 |
| `rsync` | 873 | Rsync 未授权 |
| `webtitle` | 80/443 | Web 标题 + 指纹识别 |
| `webpoc` | 80/443 | Web 漏洞 POC |

## 本地插件（`-local`）

```bash
fscan -local avdetect    # 杀软检测
fscan -local systeminfo  # 系统信息收集
fscan -local envinfo     # 环境变量信息
fscan -local dcinfo      # 域控信息
fscan -local fileinfo    # 敏感文件搜索
```

## NDJSON 输出 Schema（`-silent` 模式）

每行一个 JSON 对象，所有字段定义：

| 字段 | 类型 | 出现条件 | 说明 |
|------|------|----------|------|
| `type` | string | 必有 | `HOST` / `PORT` / `SERVICE` / `VULN` |
| `target` | string | 必有 | 原始目标 `host` 或 `host:port` |
| `status` | string | 必有 | 状态描述 |
| `host` | string | 必有 | IP 地址 |
| `port` | int | PORT/SERVICE/VULN | 端口号 |
| `service` | string | SERVICE/VULN | 服务名（ssh, smb, http 等） |
| `protocol` | string | HOST/SERVICE | 协议（ICMP, TCP, http, https） |
| `banner` | string | SERVICE | 服务 Banner |
| `title` | string | SERVICE (web) | 网页标题 |
| `url` | string | SERVICE (web) | 完整 URL |
| `vulnerability` | string | VULN | 漏洞名称 |
| `username` | string | VULN (弱口令) | 用户名 |
| `password` | string | VULN (弱口令) | 密码 |
| `plugin` | string | SERVICE/VULN | 产生结果的插件名 |
| `version` | string | SERVICE | 服务版本号 |
| `os` | string | SERVICE | 操作系统信息 |

### 输出示例

```jsonl
{"type":"HOST","target":"192.168.1.5","status":"alive","host":"192.168.1.5","protocol":"ICMP"}
{"type":"PORT","target":"192.168.1.5","status":"open","host":"192.168.1.5","port":22}
{"type":"PORT","target":"192.168.1.5","status":"open","host":"192.168.1.5","port":445}
{"type":"SERVICE","target":"192.168.1.5:22","status":"identified","host":"192.168.1.5","port":22,"service":"ssh","banner":"SSH-2.0-OpenSSH_8.9p1","version":"8.9p1","plugin":"portscan"}
{"type":"SERVICE","target":"192.168.1.5:80","status":"web","host":"192.168.1.5","port":80,"service":"http","protocol":"http","url":"http://192.168.1.5:80","title":"Welcome","plugin":"webtitle"}
{"type":"VULN","target":"192.168.1.5:445","status":"MS17-010 (Windows Server 2012 R2 Standard 9600)","host":"192.168.1.5","port":445,"vulnerability":"MS17-010","service":"smb","plugin":"ms17010"}
{"type":"VULN","target":"192.168.1.5:22","status":"weak_credential: root:123456","host":"192.168.1.5","port":22,"service":"ssh","username":"root","password":"123456","plugin":"ssh"}
{"type":"VULN","target":"192.168.1.5:6379","status":"Redis unauthorized","host":"192.168.1.5","port":6379,"vulnerability":"Redis unauthorized access","service":"redis","plugin":"redis"}
```

### 结果产出顺序

1. `HOST` — 存活探测阶段
2. `PORT` — 端口扫描阶段（与 SERVICE 可能交错）
3. `SERVICE` — 服务识别阶段
4. `VULN` — 漏洞/弱口令检测阶段

同一 `host:port` 可产生多条结果（PORT + SERVICE + VULN）。

## 常用场景参数组合

### 全网段快速扫描

```bash
fscan -h 192.168.1.0/24 -silent
```

### 跳过存活检测直接扫端口（目标明确时）

```bash
fscan -h 192.168.1.0/24 -silent -np
```

### 指定端口精确扫描

```bash
fscan -h 10.0.0.0/24 -silent -p 22,80,443,445,3389,3306,6379
```

### 仅存活探测

```bash
fscan -h 172.16.0.0/16 -silent -m icmp
```

### 低速隐蔽扫描

```bash
fscan -h 192.168.1.0/24 -silent -t 30 -time 5
```

### 通过 SOCKS5 代理扫描内网

```bash
fscan -h 10.0.0.0/24 -silent -socks5 127.0.0.1:1080
```

### 仅做弱口令检测

```bash
fscan -h 192.168.1.10 -silent -m ssh -user root -pwdf /path/to/passwords.txt
```

### Web 目标扫描

```bash
fscan -u https://target.com -silent -full
```

### 多目标文件批量扫描

```bash
fscan -hf targets.txt -silent -o results.json -f json
```

### 带调试日志的排障扫描

```bash
# NDJSON 到 stdout，debug 日志到文件，互不干扰
fscan -h 192.168.1.0/24 -silent -debug
# 事后查看：cat fscan_debug.log
```

## AI Agent 结果处理

### Python 管道消费

```python
import json, subprocess

proc = subprocess.Popen(
    ["fscan", "-h", "192.168.1.0/24", "-silent"],
    stdout=subprocess.PIPE, text=True
)

hosts, services, vulns = [], [], []
for line in proc.stdout:
    r = json.loads(line)
    if r["type"] == "HOST":
        hosts.append(r["host"])
    elif r["type"] == "SERVICE":
        services.append(r)
    elif r["type"] == "VULN":
        vulns.append(r)

proc.wait()
```

### jq 过滤

```bash
# 提取所有弱口令
fscan -h 10.0.0.0/24 -silent | jq -r 'select(.username != null) | "\(.host):\(.port) \(.service) \(.username):\(.password)"'

# 提取所有漏洞
fscan -h 10.0.0.0/24 -silent | jq -r 'select(.type=="VULN") | "\(.host):\(.port) \(.vulnerability)"'

# 提取 Web 服务
fscan -h 10.0.0.0/24 -silent | jq -r 'select(.url != null) | "\(.url) \(.title)"'

# 统计开放端口
fscan -h 10.0.0.0/24 -silent | jq -r 'select(.type=="PORT") | .port' | sort -n | uniq -c | sort -rn
```

## 注意事项

- `-silent` 抑制所有人类可读日志，stdout 仅输出 NDJSON
- 空字段不出现在 JSON 中（`omitempty`）
- 进程退出码 `0` 正常完成，非 `0` 表示参数错误或初始化失败
- `-silent` 和 `-debug` 可同时使用，互不干扰
- SOCKS5 代理下 fscan 信任协议层连接结果，不做额外深度验证
- 扫描大网段时线程数会自动调整，资源耗尽时自适应降级
- 默认超时 3 秒，防火墙 drop 的端口会静默超时，不计入失败率
