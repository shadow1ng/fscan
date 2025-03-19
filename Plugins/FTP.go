package Plugins

import (
	"fmt"
	"github.com/jlaffaye/ftp"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"time"
)

func FtpScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	Common.LogDebug(fmt.Sprintf("Starting scan %s", target))
	Common.LogDebug("Attempting anonymous login...")

	// Attempt anonymous login
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		success, dirs, err := FtpConn(info, "anonymous", "")
		if success && err == nil {
			Common.LogSuccess("Anonymous login successful!")

			// Save anonymous login result
			result := &Common.ScanResult{
				Time:   time.Now(),
				Type:   Common.VULN,
				Target: info.Host,
				Status: "vulnerable",
				Details: map[string]interface{}{
					"port":        info.Ports,
					"service":     "ftp",
					"username":    "anonymous",
					"password":    "",
					"type":        "anonymous-login",
					"directories": dirs,
				},
			}
			Common.SaveResult(result)
			return nil
		}
		errlog := fmt.Sprintf("ftp %s %v", target, err)
		Common.LogError(errlog)
		break
	}

	totalUsers := len(Common.Userdict["ftp"])
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("Starting username and password combinations (Total users: %d, Total passwords: %d)", totalUsers, totalPass))

	tried := 0
	total := totalUsers * totalPass

	// Iterate through username and password combinations
	for _, user := range Common.Userdict["ftp"] {
		for _, pass := range Common.Passwords {
			tried++
			pass = strings.Replace(pass, "{user}", user, -1)
			Common.LogDebug(fmt.Sprintf("[%d/%d] Trying: %s:%s", tried, total, user, pass))

			var lastErr error

			// Retry loop
			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				if retryCount > 0 {
					Common.LogDebug(fmt.Sprintf("Retry %d: %s:%s", retryCount+1, user, pass))
				}

				done := make(chan struct {
					success bool
					dirs    []string
					err     error
				}, 1)

				go func(user, pass string) {
					success, dirs, err := FtpConn(info, user, pass)
					select {
					case done <- struct {
						success bool
						dirs    []string
						err     error
					}{success, dirs, err}:
					default:
					}
				}(user, pass)

				select {
				case result := <-done:
					if result.success && result.err == nil {
						successLog := fmt.Sprintf("FTP service %s successfully brute-forced Username: %v Password: %v", target, user, pass)
						Common.LogSuccess(successLog)

						// Save brute-force success result
						vulnResult := &Common.ScanResult{
							Time:   time.Now(),
							Type:   Common.VULN,
							Target: info.Host,
							Status: "vulnerable",
							Details: map[string]interface{}{
								"port":        info.Ports,
								"service":     "ftp",
								"username":    user,
								"password":    pass,
								"type":        "weak-password",
								"directories": result.dirs,
							},
						}
						Common.SaveResult(vulnResult)
						return nil
					}
					lastErr = result.err
				case <-time.After(time.Duration(Common.Timeout) * time.Second):
					lastErr = fmt.Errorf("Connection timeout")
				}

				// Error handling
				if lastErr != nil {
					errlog := fmt.Sprintf("FTP service %s attempt failed Username: %v Password: %v Error: %v",
						target, user, pass, lastErr)
					Common.LogError(errlog)

					if strings.Contains(lastErr.Error(), "Login incorrect") {
						break
					}

					if strings.Contains(lastErr.Error(), "too many connections") {
						Common.LogDebug("Too many connections, waiting 5 seconds...")
						time.Sleep(5 * time.Second)
						if retryCount < maxRetries-1 {
							continue
						}
					}
				}
			}
		}
	}

	Common.LogDebug(fmt.Sprintf("Scan complete, tried %d combinations", tried))
	return tmperr
}

// FtpConn establishes an FTP connection and attempts login
func FtpConn(info *Common.HostInfo, user string, pass string) (success bool, directories []string, err error) {
	Host, Port := info.Host, info.Ports

	// Establish FTP connection
	conn, err := ftp.DialTimeout(fmt.Sprintf("%v:%v", Host, Port), time.Duration(Common.Timeout)*time.Second)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		if conn != nil {
			conn.Quit()
		}
	}()

	// Attempt login
	if err = conn.Login(user, pass); err != nil {
		return false, nil, err
	}

	// Get directory information
	dirs, err := conn.List("")
	if err == nil && len(dirs) > 0 {
		directories = make([]string, 0, min(6, len(dirs)))
		for i := 0; i < len(dirs) && i < 6; i++ {
			name := dirs[i].Name
			if len(name) > 50 {
				name = name[:50]
			}
			directories = append(directories, name)
		}
	}

	return true, directories, nil
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
