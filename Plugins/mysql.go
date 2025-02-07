package Plugins

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/shadow1ng/fscan/common"
	"strings"
	"time"
)

func MysqlScan(info *common.HostInfo) (tmperr error) {
	if common.IsBrute {
		return
	}
	starttime := time.Now().Unix()
	for _, user := range common.Userdict["mysql"] {
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := MysqlConn(info, user, pass)
			if flag == true && err == nil {
				return err
			} else {
				errlog := fmt.Sprintf("[-] mysql %v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
				common.LogError(errlog)
				tmperr = err
				if common.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(common.Userdict["mysql"])*len(common.Passwords)) * common.Timeout) {
					return err
				}
			}
		}
	}
	return tmperr
}

func MysqlConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	for _, database := range []string{"mysql", "information_schema"} {
		dsn := fmt.Sprintf("%v:%v@tcp(%v:%v)/%v?charset=utf8&timeout=%v", Username, Password, Host, Port, database, time.Duration(common.Timeout)*time.Second)
		db, err := sql.Open("mysql", dsn)
		if err == nil {
			db.SetConnMaxLifetime(time.Duration(common.Timeout) * time.Second)
			db.SetConnMaxIdleTime(time.Duration(common.Timeout) * time.Second)
			db.SetMaxIdleConns(0)
			err = db.Ping()
			if err == nil {
				result := fmt.Sprintf("[+] mysql %v:%v:%v %v", Host, Port, Username, Password)
				common.LogSuccess(result)
				flag = true
				_ = db.Close()
				break
			}
		}
		_ = db.Close()
	}
	return flag, err
}
