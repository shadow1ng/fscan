package Plugins

import (
	"database/sql"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/Config"
	_ "github.com/sijms/go-ora/v2"
	"strings"
	"time"
)

// OracleScan 执行Oracle服务扫描
func OracleScan(info *Config.HostInfo) (tmperr error) {
	if Common.IsBrute {
		return
	}
	fmt.Println("[+] Oracle扫描模块开始...")

	starttime := time.Now().Unix()

	// 尝试用户名密码组合
	for _, user := range Common.Userdict["oracle"] {
		for _, pass := range Common.Passwords {
			// 替换密码中的用户名占位符
			pass = strings.Replace(pass, "{user}", user, -1)

			flag, err := OracleConn(info, user, pass)
			if flag && err == nil {
				return err
			}

			// 记录错误信息
			errlog := fmt.Sprintf("[-] Oracle %v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
			Common.LogError(errlog)
			tmperr = err

			if Common.CheckErrs(err) {
				return err
			}

			// 超时检查
			if time.Now().Unix()-starttime > (int64(len(Common.Userdict["oracle"])*len(Common.Passwords)) * Common.Timeout) {
				return err
			}
		}
	}
	fmt.Println("[+] Oracle扫描模块结束...")
	return tmperr
}

// OracleConn 尝试Oracle连接
func OracleConn(info *Config.HostInfo, user string, pass string) (bool, error) {
	host, port, username, password := info.Host, info.Ports, user, pass
	timeout := time.Duration(Common.Timeout) * time.Second

	// 构造连接字符串
	connStr := fmt.Sprintf("oracle://%s:%s@%s:%s/orcl",
		username, password, host, port)

	// 建立数据库连接
	db, err := sql.Open("oracle", connStr)
	if err != nil {
		return false, err
	}
	defer db.Close()

	// 设置连接参数
	db.SetConnMaxLifetime(timeout)
	db.SetConnMaxIdleTime(timeout)
	db.SetMaxIdleConns(0)

	// 测试连接
	if err = db.Ping(); err != nil {
		return false, err
	}

	// 连接成功
	result := fmt.Sprintf("[+] Oracle %v:%v:%v %v", host, port, username, password)
	Common.LogSuccess(result)
	return true, nil
}
