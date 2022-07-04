package Plugins

import (
	"database/sql"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	_ "github.com/sijms/go-ora/v2"
	"time"
)

type OracleConn struct{}

func OracleScan(info *common.HostInfo) (tmperr error) {
	if common.IsBrute {
		return
	}
	oracleConn := &OracleConn{}
	bt := common.InitBruteThread("oracle", info, common.Timeout, oracleConn)
	return bt.Run()
}

func (o *OracleConn) Attack(info *common.HostInfo, user string, pass string, timeout int64) (flag bool, err error) {
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
