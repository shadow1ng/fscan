package Plugins

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/Config"
	"strings"
	"time"
)

func MysqlScan(info *Config.HostInfo) (tmperr error) {
	if Common.IsBrute {
		return
	}
	starttime := time.Now().Unix()
	for _, user := range Common.Userdict["mysql"] {
		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := MysqlConn(info, user, pass)
			if flag == true && err == nil {
				return err
			} else {
				errlog := fmt.Sprintf("[-] mysql %v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
				Common.LogError(errlog)
				tmperr = err
				if Common.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(Common.Userdict["mysql"])*len(Common.Passwords)) * Common.Timeout) {
					return err
				}
			}
		}
	}
	return tmperr
}

func MysqlConn(info *Config.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	dataSourceName := fmt.Sprintf("%v:%v@tcp(%v:%v)/mysql?charset=utf8&timeout=%v", Username, Password, Host, Port, time.Duration(Common.Timeout)*time.Second)
	db, err := sql.Open("mysql", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(Common.Timeout) * time.Second)
		db.SetConnMaxIdleTime(time.Duration(Common.Timeout) * time.Second)
		db.SetMaxIdleConns(0)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("[+] mysql %v:%v:%v %v", Host, Port, Username, Password)
			Common.LogSuccess(result)
			flag = true
		}
	}
	return flag, err
}
