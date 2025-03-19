package Plugins

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"io"
	"net"
	"strings"
	"time"
)

// IMAPScan main scan function
func IMAPScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	Common.LogDebug(fmt.Sprintf("Starting scan %s", target))
	totalUsers := len(Common.Userdict["imap"])
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("Starting username and password combinations (Total users: %d, Total passwords: %d)", totalUsers, totalPass))

	tried := 0
	total := totalUsers * totalPass

	for _, user := range Common.Userdict["imap"] {
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
					success, err := IMAPConn(info, user, pass)
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
					if result.success {
						successMsg := fmt.Sprintf("IMAP service %s brute-forced successfully Username: %v Password: %v", target, user, pass)
						Common.LogSuccess(successMsg)

						// Save result
						vulnResult := &Common.ScanResult{
							Time:   time.Now(),
							Type:   Common.VULN,
							Target: info.Host,
							Status: "vulnerable",
							Details: map[string]interface{}{
								"port":     info.Ports,
								"service":  "imap",
								"username": user,
								"password": pass,
								"type":     "weak-password",
							},
						}
						Common.SaveResult(vulnResult)
						return nil
					}
				case <-time.After(time.Duration(Common.Timeout) * time.Second):
					err = fmt.Errorf("Connection timeout")
				}

				if err != nil {
					errMsg := fmt.Sprintf("IMAP service %s attempt failed Username: %v Password: %v Error: %v", target, user, pass, err)
					Common.LogError(errMsg)

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

// IMAPConn connection test function
func IMAPConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second
	addr := fmt.Sprintf("%s:%s", host, port)

	// Attempt plain connection
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err == nil {
		if flag, err := tryIMAPAuth(conn, user, pass, timeout); err == nil {
			return flag, nil
		}
		conn.Close()
	}

	// Attempt TLS connection
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, tlsConfig)
	if err != nil {
		return false, fmt.Errorf("Connection failed: %v", err)
	}
	defer conn.Close()

	return tryIMAPAuth(conn, user, pass, timeout)
}

// tryIMAPAuth attempts IMAP authentication
func tryIMAPAuth(conn net.Conn, user string, pass string, timeout time.Duration) (bool, error) {
	conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	_, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("Failed to read welcome message: %v", err)
	}

	loginCmd := fmt.Sprintf("a001 LOGIN \"%s\" \"%s\"\r\n", user, pass)
	_, err = conn.Write([]byte(loginCmd))
	if err != nil {
		return false, fmt.Errorf("Failed to send login command: %v", err)
	}

	for {
		conn.SetDeadline(time.Now().Add(timeout))
		response, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return false, fmt.Errorf("Authentication failed")
			}
			return false, fmt.Errorf("Failed to read response: %v", err)
		}

		if strings.Contains(response, "a001 OK") {
			return true, nil
		}

		if strings.Contains(response, "a001 NO") || strings.Contains(response, "a001 BAD") {
			return false, fmt.Errorf("Authentication failed")
		}
	}
}
