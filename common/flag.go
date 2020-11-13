package common

import (
	"flag"
)

func Banner(){
	banner := `

   ___                              _    
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _`+"`"+` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
`
	print(banner)
}




func Flag(Info *HostInfo)  {
	Banner()
	Ports := "21,22,23,80,135,443,445,1433,1521,3306,5432,6379,7001,8080,8089,9000,9200,11211,27017"
	flag.StringVar(&Info.Host,"h","","IP address of the host you want to scan,for example: 192.168.11.11 | 192.168.11.11-255 | 192.168.11.11,192.168.11.12")
	flag.StringVar(&Info.Ports,"p",Ports,"Select a port,for example: 22 | 1-65535 | 22,80,3306")
	flag.StringVar(&Info.Command,"c","","exec command (ssh)")
	flag.IntVar(&Info.Threads,"t",100,"Thread nums")
	flag.BoolVar(&Info.Isping,"np",false,"not to ping")
	flag.BoolVar(&Info.IsSave,"no",false,"not to save output log")
	flag.StringVar(&Info.Username,"user","","username")
	flag.StringVar(&Info.Userfile,"userf","","username file")
	flag.StringVar(&Info.Password,"pwd","","password")
	flag.StringVar(&Info.Passfile,"pwdf","","password file")
	flag.StringVar(&Info.Outputfile,"o","result.txt","Outputfile")
	flag.Int64Var(&Info.Timeout,"time",3,"Set timeout")
	flag.StringVar(&Info.Scantype,"m","all","Select scan type ,as: -m ssh")
	flag.StringVar(&Info.RedisFile,"rf","","redis file to write sshkey file (as: -rf id_rsa.pub) ")
	flag.StringVar(&Info.RedisFile,"rs","","redis shell to write cron file (as: -rs 127.0.0.1:4444) ")
	flag.Parse()
}