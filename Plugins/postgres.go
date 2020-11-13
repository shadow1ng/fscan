package Plugins

import (
	"../common"
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"strings"
	"sync"
	"time"
)

func PostgresScan(info *common.HostInfo,ch chan int,wg *sync.WaitGroup) {
Loop:
	for _,user:=range common.Userdict["postgresql"]{
		for _,pass:=range common.Passwords{
			pass = strings.Replace(pass, "{user}", string(user), -1)
			flag,err := PostgresConn(info,user,pass,ch,wg)
			if flag==true && err==nil {
				break Loop
			}
		}
	}
	wg.Done()
	<- ch
}

func PostgresConn(info *common.HostInfo,user string,pass string,ch chan int,wg *sync.WaitGroup)(flag bool,err error){
	flag = false
	Host,Port,Username,Password := info.Host, common.PORTList["psql"],user, pass
	dataSourceName := fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=%v", Username, Password, Host,Port, "postgres", "disable")
	db, err := sql.Open("mysql", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(info.Timeout)*time.Second)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("Postgres:%v:%v:%v %v",Host,Port,Username,Password)
			common.LogSuccess(result)
			flag = true
		}
	}
	return flag,err
}


