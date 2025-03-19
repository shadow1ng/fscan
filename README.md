# Fscan 2.0.0
[English](README.md) | [中文](README_CN.md)

# 0x00 New Features

1. UI/UX optimization

2. Added -f and -o parameters, -f supports txt/csv/json, output format optimization

3. Added port fingerprint recognition feature.

4. Added local information collection module, local domain control detection module, and local Minidump module

5. Added scanning for Telnet, VNC, Elasticsearch, RabbitMQ, Kafka, ActiveMQ, LDAP, SMTP, IMAP, POP3, SNMP, Zabbix, Modbus, Rsync, Cassandra, Neo4j.

6. Architecture refactoring, built with reflection + plugin modules

7. Added -log parameter, supports INFO, SUCCESS, ERROR, DEBUG parameters for debugging specific information.

8. Optimized threading, now runs with better multithreading

**Due to the comprehensive refactoring of the old version code, there may inevitably be bugs. Please submit an issue if you encounter any bugs, and they will be fixed as soon as possible. Thank you.**

**Welcome to submit new plugin modules. Currently, plugins are in a quick hot-plug form, suitable for easy development.**

# 0x01 Introduction

A comprehensive internal network scanning tool with rich features, providing one-click automated, all-around vulnerability scanning capabilities.

## Main Features

- Host live detection: Quickly identify active hosts in the internal network
- Port scanning: Fully detect open ports on target hosts
- Service brute force: Support password brute force testing for common services
- Vulnerability exploitation: Integrated high-risk vulnerability detection such as MS17-010
- Redis exploitation: Support batch writing of public keys for permission acquisition
- System information collection: Can read Windows network card information
- Web application detection:
  - Web fingerprint recognition
  - Web vulnerability scanning
- Domain environment detection:
  - NetBIOS information acquisition
  - Domain controller identification
- Post-exploitation features: Support for reverse shell through scheduled tasks

# 0x02 Main Features
## 1. Information Collection
- ICMP-based host live detection: Quickly identify active host devices in the network
- Comprehensive port scanning: Systematically detect open ports on target hosts

## 2. Brute Force Features
- Common service password brute force: Support authentication testing for multiple protocols such as SSH, SMB, RDP
- Database password brute force: Cover mainstream database systems such as MySQL, MSSQL, Redis, PostgreSQL, Oracle

## 3. System Information and Vulnerability Scanning
- Network information collection: Including NetBIOS detection and domain controller identification
- System information acquisition: Able to read network card configuration information of the target system
- Security vulnerability detection: Support identification and detection of high-risk vulnerabilities such as MS17-010

## 4. Web Application Detection
- Website information collection: Automatically obtain website title information
- Web fingerprint recognition: Can identify common CMS systems and OA frameworks
- Vulnerability scanning capabilities: Integrated vulnerability detection for WebLogic, Struts2, etc., compatible with XRay POC

## 5. Vulnerability Exploitation Modules
- Redis exploitation: Support writing public keys or implanting scheduled tasks
- SSH remote execution: Provide SSH command execution function
- MS17-010 exploitation: Support ShellCode injection, can perform operations such as adding users

## 6. Auxiliary Features
- Scan result storage: Save all detection results to a file for subsequent analysis

# 0x03 Usage Instructions

## Basic Scan Configuration

**Due to refactoring, not all parameters can be guaranteed to work properly. Please submit an issue if you encounter any problems.**

**Target Configuration**

```
-h      Specify target (supports formats: 192.168.1.1/24, 192.168.1.1-255, 192.168.1.1,192.168.1.2)
-eh     Exclude specific targets
-hf     Import targets from file
```

**Port Configuration**
```
-p      Specify port range (default common ports), e.g., -p 22,80,3306 or -p 1-65535
-portf  Import port list from file
```

## Authentication Configuration

**Username and Password**
```
-user   Specify username
-pwd    Specify password
-userf  Username dictionary file
-pwdf   Password dictionary file
-usera  Add additional username
-pwda   Add additional password
-domain Specify domain
```

**SSH Related**
```
-sshkey SSH private key path
-c      Command to execute after SSH connection
```

## Scan Control

**Scan Mode**
```
-m      Specify scan mode (default is All)
-t      Number of threads (default 60)
-time   Timeout (default 3 seconds)
-top    Display number of live detection results (default 10)
-np     Skip live detection
-ping   Use ping instead of ICMP
-skip   Skip fingerprint recognition
```

## Web Scan Configuration

```
-u      Specify single URL scan
-uf     Import URL list from file
-cookie Set Cookie
-wt     Web request timeout (default 5 seconds)
```

## Proxy Settings

```
-proxy  HTTP proxy (e.g., http://127.0.0.1:8080)
-socks5 SOCKS5 proxy (e.g., 127.0.0.1:1080)
```

## POC Scan Configuration

```
-pocpath POC file path
-pocname Specify POC name
-full    Enable full POC scan
-dns     Enable DNS log
-num     POC concurrency (default 20)
```

## Redis Exploitation Configuration

```
-rf      Redis file name
-rs      Redis Shell configuration
-noredis Disable Redis detection
```

## Output Control

```
-o       Output file path (default off)
-f       Output format (default txt)
-no      Disable result saving
-silent  Silent mode
-nocolor Disable color output
-json    JSON format output
-log     Log level setting
-pg      Display scan progress bar
```

## Other Configuration

```
-local   Local mode
-nobr    Disable brute force
-retry   Maximum retry times (default 3)
-path    Remote path configuration
-hash    Hash value
-hashf   Hash file
-sc      Shellcode configuration
-wmi     Enable WMI
-lang    Language setting (default zh)
```

**Due to refactoring, not all parameters can be guaranteed to work properly. Please submit an issue if you encounter any problems.**

## Compilation Instructions

```bash
# Basic compilation
go build -ldflags="-s -w" -trimpath main.go

# UPX compression (optional)
upx -9 fscan
```

## System Installation
```bash
# Arch Linux
yay -S fscan-git
# or
paru -S fscan-git
```

# 0x04 Screenshots

`fscan.exe -h 192.168.x.x  (full functionality, ms17010, read network card information)`
![](image/1.png)

![](image/4.png)

`fscan.exe -h 192.168.x.x -rf id_rsa.pub (redis write public key)`
![](image/2.png)

`fscan.exe -h 192.168.x.x -c "whoami;id" (ssh command)`
![](image/3.png)

`fscan.exe -h 192.168.x.x -p80 -proxy http://127.0.0.1:8080 one-click support for xray's poc`
![](image/2020-12-12-13-34-44.png)

`fscan.exe -h 192.168.x.x -p 139 (netbios detection, domain control identification, the [+]DC in the picture represents domain control)`
![](image/netbios.png)

`go run .\main.go -h 192.168.x.x/24 -m netbios (when using -m netbios, complete netbios information will be displayed)`
![](image/netbios1.png)

`go run .\main.go -h 192.0.0.0/8 -m icmp (detect the gateway and several random IPs of each C segment, and count the top 10 B and C segment live counts)`
![img.png](image/live.png)

New display

![2.0-1](image/2.0-1.png)

![2.0-2](image/2.0-2.png)

# 0x05 Disclaimer

This tool is only for **legally authorized** enterprise security construction activities. If you need to test the availability of this tool, please set up your own target environment.

To avoid malicious use, all included POCs in this project are theoretical judgments of vulnerabilities, without the process of exploiting vulnerabilities, and will not launch real attacks and exploit vulnerabilities on the target.

When using this tool for detection, you should ensure that the behavior complies with local laws and regulations and has obtained sufficient authorization. **Do not scan unauthorized targets.**

If you engage in any illegal behavior while using this tool, you will bear the corresponding consequences yourself, and we will not bear any legal and joint liability.

Before installing and using this tool, please **read and fully understand the content of each clause carefully**, and pay special attention to the clauses that limit, exempt, or involve your significant rights and interests, which may be highlighted in bold or underlined.

Unless you have fully read, fully understood, and accepted all the terms of this agreement, please do not install and use this tool. Your use behavior or your express or implied acceptance of this agreement will be deemed as you have read and agreed to be bound by this agreement.

# 0x06 404StarLink 2.0 - Galaxy
![](https://github.com/knownsec/404StarLink-Project/raw/master/logo.png)

fscan is part of the 404Team [StarLink Project 2.0](https://github.com/knownsec/404StarLink2.0-Galaxy). If you have any questions about fscan or want to find partners to communicate with, you can refer to the StarLink Project's group joining method.

- [https://github.com/knownsec/404StarLink2.0-Galaxy#community](https://github.com/knownsec/404StarLink2.0-Galaxy#community)

Demo video [【Security Tool】5 major functions, one-click internal network scanning artifact - 404 StarLink Project fscan](https://www.bilibili.com/video/BV1Cv4y1R72M)

# 0x07 Security Training
![img.png](image/5.png)
Learn network security, choose Linglong Security! Professional vulnerability mining, precise risk positioning; help skill improvement, shape security elites; Linglong Security, escort your digital world!  
Free online learning of network security, covering src vulnerability mining, 0 basic security entry. Suitable for beginners, advanced, experts: https://space.bilibili.com/602205041  
Linglong Security past students' good news🎉: https://www.ifhsec.com/list.html  
Linglong Security vulnerability mining training contact WeChat: linglongsec

# 0x08 Star Chart
[![Stargazers over time](https://starchart.cc/shadow1ng/fscan.svg)](https://starchart.cc/shadow1ng/fscan)

# 0x09 Donation
 If you think this project is helpful to you, you can buy the author a drink🍹 [Click me](image/sponsor.png)

# 0x10 Reference Links
https://github.com/Adminisme/ServerScan  
https://github.com/netxfly/x-crack  
https://github.com/hack2fun/Gscan  
https://github.com/k8gege/LadonGo   
https://github.com/jjf012/gopoc

# 0x11 Recent Updates

## 2025 Updates
 - Added plugins

## 2024 Updates
- **2024/12/19**: v2.0.0 Major Update
  - Complete code refactoring, improved performance and maintainability
  - Redesigned modular architecture, supports plugin extensions
  - Improved concurrency control, enhanced scanning efficiency

## 2023 Updates
- **2023/11/13**: 
  - Added console color output (can be turned off with `-nocolor`)
  - Support saving results in JSON format (`-json`)
  - Adjusted minimum TLS version to 1.0
  - Support port grouping (`-p db,web,service`)

## 2022 Updates
- **2022/11/19**: Added hash collision and wmiexec command execution without echo
- **2022/7/14**: Improved file import support and search matching functionality
- **2022/7/6**: Optimized memory management, extended URL support
- **2022/7/2**: 
  - Enhanced POC fuzz module
  - Added MS17017 exploitation feature
  - Added socks5 proxy support
- **2022/4/20**: Added POC path specification and port file import functionality
- **2022/2/25**: Added webonly mode (thanks @AgeloVito)
- **2022/1/11**: Added Oracle password brute force
- **2022/1/7**: Improved large-scale segment scanning, added LiveTop feature

## 2021 Updates
- **2021/12/7**: Added RDP scanning feature
- **2021/12/1**: Comprehensive optimization of functional modules
- **2021/6/18**: Improved POC recognition mechanism
- **2021/5/29**: Added FCGI unauthorized scanning
- **2021/5/15**: Released Windows 2003 version
- **2021/5/6**: Updated core modules
- **2021/4/21**: Added NetBIOS detection and domain control identification
- **2021/3/4**: Support batch URL scanning
- **2021/2/25**: Support password brute force feature
- **2021/2/8**: Added fingerprint recognition feature
- **2021/2/5**: Optimized ICMP detection

## 2020 Updates
- **2020/12/12**: Integrated YAML parsing engine, supports XRay POC
- **2020/12/6**: Optimized ICMP module
- **2020/12/03**: Improved IP segment handling
- **2020/11/17**: Added WebScan module
- **2020/11/16**: Optimized ICMP module
- **2020/11/15**: Support file import IP

_Thanks to all developers who contributed to the project_
