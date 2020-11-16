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
	flag.StringVar(&Info.Host,"h","","IP address of the host you want to scan,for example: 192.168.11.11 | 192.168.11.11-255 | 192.168.11.11,192.168.11.12")
	flag.StringVar(&Info.HostFile,"hf","","host file, -hs ip.txt")
	flag.StringVar(&Info.Ports,"p",DefaultPorts,"Select a port,for example: 22 | 1-65535 | 22,80,3306")
	flag.StringVar(&Info.Command,"c","","exec command (ssh)")
	flag.IntVar(&Info.Threads,"t",200,"Thread nums")
	flag.IntVar(&Info.IcmpThreads,"it",3000,"Icmp Threads nums")
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
	flag.StringVar(&Info.RedisShell,"rs","","redis shell to write cron file (as: -rs 192.168.1.1:6666) ")
	flag.Parse()
}