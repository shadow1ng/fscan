package Plugins

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"
	_ "github.com/sijms/go-ora/v2"
)

func OracleScan(info common.HostInfo, flags common.Flags) (tmperr error) {
	if flags.IsBrute {
		return
	}
	starttime := time.Now().Unix()
	for _, user := range common.Userdict["oracle"] {
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := OracleConn(info, user, pass, flags.Timeout)
			if flag && err == nil {
				return err
			} else {
				errlog := fmt.Sprintf("[-] oracle %v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
				common.LogError(errlog)
				tmperr = err
				if common.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(common.Userdict["oracle"])*len(common.Passwords)) * flags.Timeout) {
					return err
				}
			}
		}
	}
	return tmperr
}

func OracleConn(info common.HostInfo, user string, pass string, timeout int64) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	dataSourceName := fmt.Sprintf("oracle://%s:%s@%s:%s/orcl", Username, Password, Host, Port)
	db, err := sql.Open("oracle", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(timeout) * time.Second)
		db.SetConnMaxIdleTime(time.Duration(timeout) * time.Second)
		db.SetMaxIdleConns(0)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("[+] oracle:%v:%v:%v %v", Host, Port, Username, Password)
			common.LogSuccess(result)
			flag = true
		}
	}
	return flag, err
}
