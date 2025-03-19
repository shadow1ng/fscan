package Plugins

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net/http"
	"strings"
	"time"
)

func ElasticScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	Common.LogDebug(fmt.Sprintf("Starting scan %s", target))
	Common.LogDebug("Trying unauthenticated access...")

	// First test unauthenticated access
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		if retryCount > 0 {
			Common.LogDebug(fmt.Sprintf("Retrying unauthenticated access for the %d time", retryCount+1))
		}
		flag, err := ElasticConn(info, "", "")
		if flag && err == nil {
			successMsg := fmt.Sprintf("Elasticsearch service %s does not require authentication", target)
			Common.LogSuccess(successMsg)

			// Save unauthenticated access result
			result := &Common.ScanResult{
				Time:   time.Now(),
				Type:   Common.VULN,
				Target: info.Host,
				Status: "vulnerable",
				Details: map[string]interface{}{
					"port":    info.Ports,
					"service": "elasticsearch",
					"type":    "unauthorized-access",
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

	totalUsers := len(Common.Userdict["elastic"])
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("Starting to try username and password combinations (Total users: %d, Total passwords: %d)",
		totalUsers, totalPass))

	tried := 0
	total := totalUsers * totalPass

	// Iterate over all username and password combinations
	for _, user := range Common.Userdict["elastic"] {
		for _, pass := range Common.Passwords {
			tried++
			pass = strings.Replace(pass, "{user}", user, -1)
			Common.LogDebug(fmt.Sprintf("[%d/%d] Trying: %s:%s", tried, total, user, pass))

			// Retry loop
			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				if retryCount > 0 {
					Common.LogDebug(fmt.Sprintf("Retrying for the %d time: %s:%s", retryCount+1, user, pass))
				}

				done := make(chan struct {
					success bool
					err     error
				}, 1)

				go func(user, pass string) {
					flag, err := ElasticConn(info, user, pass)
					select {
					case done <- struct {
						success bool
						err     error
					}{flag, err}:
					default:
					}
				}(user, pass)

				var err error
				select {
				case result := <-done:
					err = result.err
					if result.success && err == nil {
						successMsg := fmt.Sprintf("Elasticsearch service %s brute force successful Username: %v Password: %v",
							target, user, pass)
						Common.LogSuccess(successMsg)

						// Save weak password result
						vulnResult := &Common.ScanResult{
							Time:   time.Now(),
							Type:   Common.VULN,
							Target: info.Host,
							Status: "vulnerable",
							Details: map[string]interface{}{
								"port":     info.Ports,
								"service":  "elasticsearch",
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
					errlog := fmt.Sprintf("Elasticsearch service %s attempt failed Username: %v Password: %v Error: %v",
						target, user, pass, err)
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

// ElasticConn attempts to connect to Elasticsearch
func ElasticConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	baseURL := fmt.Sprintf("http://%s:%s", host, port)
	req, err := http.NewRequest("GET", baseURL+"/_cat/indices", nil)
	if err != nil {
		return false, err
	}

	if user != "" || pass != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req.Header.Add("Authorization", "Basic "+auth)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200, nil
}
