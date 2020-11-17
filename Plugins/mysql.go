package Plugins

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/shadow1ng/fscan/common"
)

func MysqlScan(info *common.HostInfo, ch chan int, wg *sync.WaitGroup) {
Loop:
	for _, user := range common.Userdict["mysql"] {
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := MysqlConn(info, user, pass)
			if flag == true && err == nil {
				break Loop
			}
		}
	}
	wg.Done()
	<-ch
}

func MysqlConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, common.PORTList["mysql"], user, pass
	dataSourceName := fmt.Sprintf("%v:%v@tcp(%v:%v)/%v?charset=utf8", Username, Password, Host, Port, "mysql")
	db, err := sql.Open("mysql", dataSourceName)
	db.SetConnMaxLifetime(time.Duration(info.Timeout) * time.Second)
	if err == nil {
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("mysql:%v:%v:%v %v", Host, Port, Username, Password)
			common.LogSuccess(result)
			flag = true
		}
	}
	return flag, err
}
