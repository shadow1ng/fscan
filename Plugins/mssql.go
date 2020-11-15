package Plugins

import (
	"../common"
	"database/sql"
	"fmt"
	_ "github.com/denisenkom/go-mssqldb"
	"strings"
	"sync"
	"time"
)




func MssqlScan(info *common.HostInfo,ch chan int,wg *sync.WaitGroup) {
Loop:
	for _,user:=range common.Userdict["mssql"]{
		for _,pass:=range common.Passwords{
			pass = strings.Replace(pass, "{user}", user, -1)
			flag,err := MssqlConn(info,user,pass)
			if flag==true && err==nil {
				break Loop
			}
		}
	}
	wg.Done()
	<- ch
}

func MssqlConn(info *common.HostInfo,user string,pass string)(flag bool,err error){
	flag = false
	Host,Port,Username,Password := info.Host, common.PORTList["mssql"],user, pass
	dataSourceName := fmt.Sprintf("server=%s;user id=%s;password=%s;port=%d;encrypt=disable;timeout=%d", Host,Username,Password,Port,time.Duration(info.Timeout)*time.Second)
	db, err := sql.Open("mssql", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(info.Timeout)*time.Second)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("mssql:%v:%v:%v %v",Host,Port,Username,Password)
			common.LogSuccess(result)
			flag = true
		}
	}
	return flag,err
}

