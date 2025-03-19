package Plugins

import (
	"fmt"
	"github.com/IBM/sarama"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"time"
)

func KafkaScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("Starting scan %s", target))

	// Attempt unauthenticated access
	Common.LogDebug("Attempting unauthenticated access...")
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		if retryCount > 0 {
			Common.LogDebug(fmt.Sprintf("Retry %d for unauthenticated access", retryCount+1))
		}
		flag, err := KafkaConn(info, "", "")
		if flag && err == nil {
			// Save unauthenticated access result
			result := &Common.ScanResult{
				Time:   time.Now(),
				Type:   Common.VULN,
				Target: info.Host,
				Status: "vulnerable",
				Details: map[string]interface{}{
					"port":    info.Ports,
					"service": "kafka",
					"type":    "unauthorized-access",
				},
			}
			Common.SaveResult(result)
			Common.LogSuccess(fmt.Sprintf("Kafka service %s can be accessed without authentication", target))
			return nil
		}
		if err != nil && Common.CheckErrs(err) != nil {
			if retryCount < maxRetries-1 {
				continue
				}
			return err
		}
		break
	}

	totalUsers := len(Common.Userdict["kafka"])
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("Starting username and password combinations (Total users: %d, Total passwords: %d)", totalUsers, totalPass))

	tried := 0
	total := totalUsers * totalPass

	// Iterate through all username and password combinations
	for _, user := range Common.Userdict["kafka"] {
		for _, pass := range Common.Passwords {
			tried++
			pass = strings.Replace(pass, "{user}", user, -1)
			Common.LogDebug(fmt.Sprintf("[%d/%d] Trying: %s:%s", tried, total, user, pass))

			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				if retryCount > 0 {
					Common.LogDebug(fmt.Sprintf("Retry %d: %s:%s", retryCount+1, user, pass))
				}

				done := make(chan struct {
					success bool
					err     error
				}, 1)

				go func(user, pass string) {
					success, err := KafkaConn(info, user, pass)
					select {
					case done <- struct {
						success bool
						err     error
					}{success, err}:
					default:
					}
				}(user, pass)

				var err error
				select {
				case result := <-done:
					err = result.err
					if result.success && err == nil {
						// Save brute-force success result
						vulnResult := &Common.ScanResult{
							Time:   time.Now(),
							Type:   Common.VULN,
							Target: info.Host,
							Status: "vulnerable",
							Details: map[string]interface{}{
								"port":     info.Ports,
								"service":  "kafka",
								"type":     "weak-password",
								"username": user,
								"password": pass,
							},
						}
						Common.SaveResult(vulnResult)
						Common.LogSuccess(fmt.Sprintf("Kafka service %s brute-forced successfully Username: %s Password: %s", target, user, pass))
						return nil
					}
				case <-time.After(time.Duration(Common.Timeout) * time.Second):
					err = fmt.Errorf("Connection timeout")
				}

				if err != nil {
					Common.LogError(fmt.Sprintf("Kafka service %s attempt failed Username: %s Password: %s Error: %v",
						target, user, pass, err))
					if retryErr := Common.CheckErrs(err); retryErr != nil {
						if retryCount == maxRetries-1 {
							continue
						}
						continue
					}
				}
				break
			}
		}
	}

	Common.LogDebug(fmt.Sprintf("Scan complete, tried %d combinations", tried))
	return tmperr
}

// KafkaConn attempts Kafka connection
func KafkaConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	config := sarama.NewConfig()
	config.Net.DialTimeout = timeout
	config.Net.TLS.Enable = false
	config.Version = sarama.V2_0_0_0

	// Set SASL configuration
	if user != "" || pass != "" {
		config.Net.SASL.Enable = true
		config.Net.SASL.Mechanism = sarama.SASLTypePlaintext
		config.Net.SASL.User = user
		config.Net.SASL.Password = pass
		config.Net.SASL.Handshake = true
	}

	brokers := []string{fmt.Sprintf("%s:%s", host, port)}

	// Attempt to connect as a consumer
	consumer, err := sarama.NewConsumer(brokers, config)
	if err == nil {
		defer consumer.Close()
		return true, nil
	}

	// If consumer connection fails, attempt to connect as a client
	client, err := sarama.NewClient(brokers, config)
	if err == nil {
		defer client.Close()
		return true, nil
	}

	// Check error type
	if strings.Contains(err.Error(), "SASL") ||
		strings.Contains(err.Error(), "authentication") ||
		strings.Contains(err.Error(), "credentials") {
		return false, fmt.Errorf("Authentication failed")
	}

	return false, err
}
