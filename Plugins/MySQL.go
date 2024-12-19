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

// MysqlScan 执行MySQL服务扫描
func MysqlScan(info *Config.HostInfo) (tmperr error) {
	if Common.IsBrute {
		return
	}
	fmt.Println("[+] Mysql扫描模块开始...")

	starttime := time.Now().Unix()

	// 尝试用户名密码组合
	for _, user := range Common.Userdict["mysql"] {
		for _, pass := range Common.Passwords {
			// 替换密码中的用户名占位符
			pass = strings.Replace(pass, "{user}", user, -1)

			flag, err := MysqlConn(info, user, pass)
			if flag && err == nil {
				return err
			}

			// 记录错误信息
			errlog := fmt.Sprintf("[-] MySQL %v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
			Common.LogError(errlog)
			tmperr = err

			if Common.CheckErrs(err) {
				return err
			}

			// 超时检查
			if time.Now().Unix()-starttime > (int64(len(Common.Userdict["mysql"])*len(Common.Passwords)) * Common.Timeout) {
				return err
			}
		}
	}
	fmt.Println("[+] Mysql扫描模块结束...")
	return tmperr
}

// MysqlConn 尝试MySQL连接
func MysqlConn(info *Config.HostInfo, user string, pass string) (bool, error) {
	host, port, username, password := info.Host, info.Ports, user, pass
	timeout := time.Duration(Common.Timeout) * time.Second

	// 构造连接字符串
	connStr := fmt.Sprintf(
		"%v:%v@tcp(%v:%v)/mysql?charset=utf8&timeout=%v",
		username, password, host, port, timeout,
	)

	// 建立数据库连接
	db, err := sql.Open("mysql", connStr)
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
	result := fmt.Sprintf("[+] MySQL %v:%v:%v %v", host, port, username, password)
	Common.LogSuccess(result)
	return true, nil
}
