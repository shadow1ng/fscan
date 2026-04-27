//go:build plugin_elasticsearch || !plugin_selective

package services

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

type ElasticsearchPlugin struct {
	plugins.BasePlugin
}

func NewElasticsearchPlugin() *ElasticsearchPlugin {
	return &ElasticsearchPlugin{
		BasePlugin: plugins.NewBasePlugin("elasticsearch"),
	}
}

func (p *ElasticsearchPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	state := session.State
	target := info.Target()

	if config.DisableBrute {
		return p.identifyService(ctx, info, config, state)
	}

	// 首先检测未授权访问
	if p.testCredential(ctx, info, Credential{Username: "", Password: ""}, config, state) {
		common.LogVuln(i18n.Tr("elasticsearch_unauth", target))
		return &ScanResult{
			Success: true,
			Type:    plugins.ResultTypeVuln,
			Service: "elasticsearch",
			VulInfo: "未授权访问",
		}
	}

	// 如果需要认证，尝试常见凭据
	credentials := GenerateCredentials("elasticsearch", config)
	if len(credentials) == 0 {
		return &ScanResult{
			Success: false,
			Service: "elasticsearch",
			Error:   fmt.Errorf("没有可用的测试凭据"),
		}
	}

	for _, cred := range credentials {
		if p.testCredential(ctx, info, cred, config, state) {
			common.LogVuln(i18n.Tr("elasticsearch_credential", target, cred.Username, cred.Password))
			return &ScanResult{
				Success:  true,
				Type:     plugins.ResultTypeCredential,
				Service:  "elasticsearch",
				Username: cred.Username,
				Password: cred.Password,
			}
		}
	}

	return &ScanResult{
		Success: false,
		Service: "elasticsearch",
		Error:   fmt.Errorf("未发现弱密码"),
	}
}

func (p *ElasticsearchPlugin) testCredential(ctx context.Context, info *common.HostInfo, cred Credential, config *common.Config, state *common.State) bool {
	client := &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// 构建URL
	protocol := "http"
	if info.Port == 9443 {
		protocol = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/", protocol, info.Host, info.Port)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}

	if cred.Username != "" || cred.Password != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(cred.Username + ":" + cred.Password))
		req.Header.Set("Authorization", "Basic "+auth)
	}

	resp, err := client.Do(req)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return false
	}
	state.IncrementTCPSuccessPacketCount()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == 200 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false
		}

		bodyStr := string(body)
		return common.ContainsAny(bodyStr, "elasticsearch", "cluster_name")
	}

	return false
}

func (p *ElasticsearchPlugin) identifyService(ctx context.Context, info *common.HostInfo, config *common.Config, state *common.State) *ScanResult {
	target := info.Target()

	if p.testCredential(ctx, info, Credential{Username: "", Password: ""}, config, state) {
		banner := "Elasticsearch"
		common.LogSuccess(i18n.Tr("elasticsearch_service", target, banner))
		return &ScanResult{
			Success: true,
				Type:     plugins.ResultTypeService,
			Service: "elasticsearch",
			Banner:  banner,
		}
	}
	return &ScanResult{
		Success: false,
		Service: "elasticsearch",
		Error:   fmt.Errorf("无法识别为Elasticsearch服务"),
	}
}

func init() {
	// 使用高效注册方式：直接传递端口信息，避免实例创建
	RegisterPluginWithPorts("elasticsearch", func() Plugin {
		return NewElasticsearchPlugin()
	}, []int{9200, 9300})
}
