package Plugins

import (
	"fmt"
	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"strings"
	"time"
)

// RabbitMQScan 执行 RabbitMQ 服务扫描
func RabbitMQScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	starttime := time.Now().Unix()

	// 首先测试默认账户 guest/guest
	flag, err := RabbitMQConn(info, "guest", "guest")
	if flag && err == nil {
		return err
	}

	// 尝试用户名密码组合
	for _, user := range Common.Userdict["rabbitmq"] {
		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)

			flag, err := RabbitMQConn(info, user, pass)
			if flag && err == nil {
				return err
			}

			errlog := fmt.Sprintf("[-] RabbitMQ服务 %v:%v 尝试失败 用户名: %v 密码: %v 错误: %v", info.Host, info.Ports, user, pass, err)
			Common.LogError(errlog)
			tmperr = err

			if Common.CheckErrs(err) {
				return err
			}

			if time.Now().Unix()-starttime > (int64(len(Common.Userdict["rabbitmq"])*len(Common.Passwords)) * Common.Timeout) {
				return err
			}
		}
	}
	return tmperr
}

// RabbitMQConn 尝试 RabbitMQ 连接
func RabbitMQConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	// 构造 AMQP URL
	amqpURL := fmt.Sprintf("amqp://%s:%s@%s:%s/", user, pass, host, port)

	// 配置连接
	config := amqp.Config{
		Dial: func(network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, timeout)
		},
	}

	// 尝试连接
	conn, err := amqp.DialConfig(amqpURL, config)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// 如果成功连接
	if conn != nil {
		result := fmt.Sprintf("[+] RabbitMQ服务 %v:%v 爆破成功 用户名: %v 密码: %v", host, port, user, pass)
		Common.LogSuccess(result)
		return true, nil
	}

	return false, fmt.Errorf("认证失败")
}
