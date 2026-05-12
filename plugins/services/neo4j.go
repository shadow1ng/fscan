//go:build plugin_neo4j || !plugin_selective

package services

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// Neo4jPlugin Neo4j扫描插件
type Neo4jPlugin struct {
	plugins.BasePlugin
}

func NewNeo4jPlugin() *Neo4jPlugin {
	return &Neo4jPlugin{
		BasePlugin: plugins.NewBasePlugin("neo4j"),
	}
}

func (p *Neo4jPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	state := session.State
	target := info.Target()

	if config.DisableBrute {
		return p.identifyService(ctx, info, config, state)
	}

	// 先测试未授权访问
	if result := p.testUnauthorizedAccess(ctx, info, config, state); result != nil && result.Success {
		common.LogVuln(i18n.Tr("neo4j_unauth", target))
		return result
	}

	credentials := GenerateCredentials("neo4j", config)
	if len(credentials) == 0 {
		return &ScanResult{
			Success: false,
			Service: "neo4j",
			Error:   fmt.Errorf("没有可用的测试凭据"),
		}
	}

	// 使用公共框架进行并发凭据测试
	authFn := p.createAuthFunc(info, config, state)
	testConfig := DefaultConcurrentTestConfigWithTarget(config, info)

	result := TestCredentialsConcurrently(ctx, credentials, authFn, "neo4j", testConfig)

	if result.Success {
		common.LogVuln(i18n.Tr("neo4j_credential", target, result.Username, result.Password))
	}

	return result
}

// createAuthFunc 创建Neo4j认证函数
func (p *Neo4jPlugin) createAuthFunc(info *common.HostInfo, config *common.Config, state *common.State) AuthFunc {
	return func(ctx context.Context, cred Credential) *AuthResult {
		return p.doNeo4jAuth(ctx, info, cred, config, state)
	}
}

// doNeo4jAuth 执行Neo4j认证
func (p *Neo4jPlugin) doNeo4jAuth(ctx context.Context, info *common.HostInfo, cred Credential, config *common.Config, state *common.State) *AuthResult {
	baseURL := fmt.Sprintf("http://%s:%d", info.Host, info.Port)

	client := &http.Client{Timeout: config.Timeout}

	req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/user/neo4j", nil)
	if err != nil {
		return &AuthResult{
			Success:   false,
			ErrorType: classifyNeo4jErrorType(err),
			Error:     err,
		}
	}

	req.SetBasicAuth(cred.Username, cred.Password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{
			Success:   false,
			ErrorType: classifyNeo4jErrorType(err),
			Error:     err,
		}
	}
	state.IncrementTCPSuccessPacketCount()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == 200 {
		return &AuthResult{
			Success:   true,
			Conn:      &neo4jConnWrapper{},
			ErrorType: ErrorTypeUnknown,
			Error:     nil,
		}
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return &AuthResult{
			Success:   false,
			ErrorType: ErrorTypeAuth,
			Error:     fmt.Errorf("认证失败，状态码: %d", resp.StatusCode),
		}
	}

	return &AuthResult{
		Success:   false,
		ErrorType: ErrorTypeUnknown,
		Error:     fmt.Errorf("未知错误，状态码: %d", resp.StatusCode),
	}
}

// neo4jConnWrapper Neo4j连接包装器
type neo4jConnWrapper struct{}

func (w *neo4jConnWrapper) Close() error {
	return nil
}

// classifyNeo4jErrorType Neo4j错误分类
func classifyNeo4jErrorType(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	neo4jAuthErrors := []string{
		"authentication failed",
		"unauthorized",
		"invalid credentials",
		"401 unauthorized",
		"403 forbidden",
	}

	return ClassifyError(err, neo4jAuthErrors, CommonNetworkErrors)
}

func (p *Neo4jPlugin) testUnauthorizedAccess(ctx context.Context, info *common.HostInfo, config *common.Config, state *common.State) *ScanResult {
	baseURL := fmt.Sprintf("http://%s:%d", info.Host, info.Port)

	client := &http.Client{Timeout: config.Timeout}

	req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/db/data/", nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return nil
	}
	state.IncrementTCPSuccessPacketCount()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == 200 {
		return &ScanResult{
			Type:    plugins.ResultTypeVuln,
			Success: true,
			Service: "neo4j",
			Banner:  "未授权访问",
		}
	}

	return nil
}

func (p *Neo4jPlugin) identifyService(ctx context.Context, info *common.HostInfo, config *common.Config, state *common.State) *ScanResult {
	target := info.Target()
	baseURL := fmt.Sprintf("http://%s:%d", info.Host, info.Port)

	client := &http.Client{Timeout: config.Timeout}

	req, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
	if err != nil {
		return &ScanResult{
			Success: false,
			Service: "neo4j",
			Error:   err,
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &ScanResult{
			Success: false,
			Service: "neo4j",
			Error:   err,
		}
	}
	state.IncrementTCPSuccessPacketCount()
	defer func() { _ = resp.Body.Close() }()

	var banner string
	serverHeader := resp.Header.Get("Server")

	if serverHeader != "" && strings.Contains(strings.ToLower(serverHeader), "neo4j") {
		banner = "Neo4j"
	} else if resp.StatusCode == 200 || resp.StatusCode == 401 {
		body, _ := io.ReadAll(resp.Body)
		if strings.Contains(strings.ToLower(string(body)), "neo4j") {
			banner = "Neo4j"
		} else {
			banner = "Neo4j"
		}
	} else {
		return &ScanResult{
			Success: false,
			Service: "neo4j",
			Error:   fmt.Errorf("无法识别为Neo4j服务"),
		}
	}

	common.LogSuccess(i18n.Tr("neo4j_service", target, banner))

	return &ScanResult{
		Type:    plugins.ResultTypeService,
		Success: true,
		Service: "neo4j",
		Banner:  banner,
	}
}

func init() {
	RegisterPluginWithPorts("neo4j", func() Plugin {
		return NewNeo4jPlugin()
	}, []int{7474, 7687, 7473})
}
