package Plugins

import (
	"database/sql"
	"fmt"
	_ "github.com/denisenkom/go-mssqldb"
	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/Config"
	"strings"
	"time"
)

// MssqlScan 执行MSSQL服务扫描
func MssqlScan(info *Config.HostInfo) (tmperr error) {
	if Common.IsBrute {
		return
	}
	fmt.Println("[+] Mssql扫描模块开始...")

	starttime := time.Now().Unix()

	// 尝试用户名密码组合
	for _, user := range Common.Userdict["mssql"] {
		for _, pass := range Common.Passwords {
			// 替换密码中的用户名占位符
			pass = strings.Replace(pass, "{user}", user, -1)

			flag, err := MssqlConn(info, user, pass)
			if flag && err == nil {
				return err
			}

			// 记录错误信息
			errlog := fmt.Sprintf("[-] MSSQL %v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
			Common.LogError(errlog)
			tmperr = err

			if Common.CheckErrs(err) {
				return err
			}

			// 超时检查
			if time.Now().Unix()-starttime > (int64(len(Common.Userdict["mssql"])*len(Common.Passwords)) * Common.Timeout) {
				return err
			}
		}
	}
	fmt.Println("[+] Mssql扫描模块结束...")
	return tmperr
}

// MssqlConn 尝试MSSQL连接
func MssqlConn(info *Config.HostInfo, user string, pass string) (bool, error) {
	host, port, username, password := info.Host, info.Ports, user, pass
	timeout := time.Duration(Common.Timeout) * time.Second

	// 构造连接字符串
	connStr := fmt.Sprintf(
		"server=%s;user id=%s;password=%s;port=%v;encrypt=disable;timeout=%v",
		host, username, password, port, timeout,
	)

	// 建立数据库连接
	db, err := sql.Open("mssql", connStr)
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
	result := fmt.Sprintf("[+] MSSQL %v:%v:%v %v", host, port, username, password)
	Common.LogSuccess(result)
	return true, nil
}
