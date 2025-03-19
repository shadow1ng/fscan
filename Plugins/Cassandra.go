package Plugins

import (
	"fmt"
	"github.com/gocql/gocql"
	"github.com/shadow1ng/fscan/Common"
	"strconv"
	"strings"
	"time"
)

func CassandraScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	maxRetries := Common.MaxRetries

	Common.LogDebug(fmt.Sprintf("Starting scan %s", target))
	Common.LogDebug("Trying unauthenticated access...")

	// First test unauthenticated access
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		if retryCount > 0 {
			Common.LogDebug(fmt.Sprintf("Retrying unauthenticated access for the %d time", retryCount+1))
		}

		flag, err := CassandraConn(info, "", "")
		if flag && err == nil {
			successMsg := fmt.Sprintf("Cassandra service %s unauthenticated access successful", target)
			Common.LogSuccess(successMsg)

			// Save unauthenticated access result
			result := &Common.ScanResult{
				Time:   time.Now(),
				Type:   Common.VULN,
				Target: info.Host,
				Status: "vulnerable",
				Details: map[string]interface{}{
					"port":        info.Ports,
					"service":     "cassandra",
					"auth_type":   "anonymous",
					"type":        "unauthorized-access",
					"description": "Database allows unauthenticated access",
				},
			}
			Common.SaveResult(result)
			return err
		}
		if err != nil && Common.CheckErrs(err) != nil {
			if retryCount == maxRetries-1 {
				return err
			}
			continue
		}
		break
	}

	totalUsers := len(Common.Userdict["cassandra"])
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("Starting to try username and password combinations (Total users: %d, Total passwords: %d)", totalUsers, totalPass))

	tried := 0
	total := totalUsers * totalPass

	// Iterate over all username and password combinations
	for _, user := range Common.Userdict["cassandra"] {
		for _, pass := range Common.Passwords {
			tried++
			pass = strings.Replace(pass, "{user}", user, -1)
			Common.LogDebug(fmt.Sprintf("[%d/%d] Trying: %s:%s", tried, total, user, pass))

			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				if retryCount > 0 {
					Common.LogDebug(fmt.Sprintf("Retrying for the %d time: %s:%s", retryCount+1, user, pass))
				}

				done := make(chan struct {
					success bool
					err     error
				}, 1)

				go func(user, pass string) {
					success, err := CassandraConn(info, user, pass)
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
						successMsg := fmt.Sprintf("Cassandra service %s brute force successful Username: %v Password: %v", target, user, pass)
						Common.LogSuccess(successMsg)

						// Save brute force success result
						vulnResult := &Common.ScanResult{
							Time:   time.Now(),
							Type:   Common.VULN,
							Target: info.Host,
							Status: "vulnerable",
							Details: map[string]interface{}{
								"port":     info.Ports,
								"service":  "cassandra",
								"username": user,
								"password": pass,
								"type":     "weak-password",
							},
						}
						Common.SaveResult(vulnResult)
						return nil
					}
				case <-time.After(time.Duration(Common.Timeout) * time.Second):
					err = fmt.Errorf("connection timeout")
				}

				if err != nil {
					errlog := fmt.Sprintf("Cassandra service %s attempt failed Username: %v Password: %v Error: %v", target, user, pass, err)
					Common.LogError(errlog)

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

	Common.LogDebug(fmt.Sprintf("Scan completed, tried %d combinations", tried))
	return tmperr
}

// CassandraConn unified connection test function
func CassandraConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	cluster := gocql.NewCluster(host)
	cluster.Port, _ = strconv.Atoi(port)
	cluster.Timeout = timeout
	cluster.ProtoVersion = 4
	cluster.Consistency = gocql.One

	if user != "" || pass != "" {
		cluster.Authenticator = gocql.PasswordAuthenticator{
			Username: user,
			Password: pass,
		}
	}

	cluster.RetryPolicy = &gocql.SimpleRetryPolicy{NumRetries: 3}

	session, err := cluster.CreateSession()
	if err != nil {
		return false, err
	}
	defer session.Close()

	var version string
	if err := session.Query("SELECT peer FROM system.peers").Scan(&version); err != nil {
		if err := session.Query("SELECT now() FROM system.local").Scan(&version); err != nil {
			return false, err
		}
	}

	return true, nil
}
