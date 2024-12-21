package Plugins

import (
	"fmt"
	"github.com/IBM/sarama"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"time"
)

// KafkaScan 执行 Kafka 服务扫描
func KafkaScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	starttime := time.Now().Unix()

	// 首先测试无认证访问
	flag, err := KafkaConn(info, "", "")
	if flag && err == nil {
		return err
	}

	// 尝试用户名密码组合
	for _, user := range Common.Userdict["kafka"] {
		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)

			flag, err := KafkaConn(info, user, pass)
			if flag && err == nil {
				return err
			}

			errlog := fmt.Sprintf("[-] Kafka服务 %v:%v 尝试失败 用户名: %v 密码: %v 错误: %v", info.Host, info.Ports, user, pass, err)
			Common.LogError(errlog)
			tmperr = err

			if Common.CheckErrs(err) {
				return err
			}

			if time.Now().Unix()-starttime > (int64(len(Common.Userdict["kafka"])*len(Common.Passwords)) * Common.Timeout) {
				return err
			}
		}
	}
	return tmperr
}

// KafkaConn 尝试 Kafka 连接
func KafkaConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	// 配置Kafka客户端
	config := sarama.NewConfig()
	config.Net.DialTimeout = timeout

	// 禁用TLS
	config.Net.TLS.Enable = false
	config.Version = sarama.V2_0_0_0 // 设置一个通用版本

	// 如果提供了认证信息
	if user != "" || pass != "" {
		config.Net.SASL.Enable = true
		config.Net.SASL.Mechanism = sarama.SASLTypePlaintext
		config.Net.SASL.User = user
		config.Net.SASL.Password = pass
	}

	// 构造broker列表
	brokers := []string{fmt.Sprintf("%s:%s", host, port)}

	// 尝试创建客户端
	client, err := sarama.NewClient(brokers, config)
	if err != nil {
		return false, err
	}
	defer client.Close()

	// 尝试获取topics列表来验证连接
	topics, err := client.Topics()
	if err != nil {
		return false, err
	}

	// 如果成功连接并获取topics
	if len(topics) >= 0 {
		result := fmt.Sprintf("[+] Kafka服务 %v:%v ", host, port)
		if user != "" {
			result += fmt.Sprintf("爆破成功 用户名: %v 密码: %v", user, pass)
		} else {
			result += "无需认证即可访问"
		}
		Common.LogSuccess(result)
		return true, nil
	}

	return false, fmt.Errorf("认证失败")
}
