//go:build linux && !no_local

package local

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shadow1ng/fscan/common"
)

func TestLocalPluginConstructors(t *testing.T) {
	tests := []struct {
		name string
		got  Plugin
	}{
		{name: "cleaner", got: NewCleanerPlugin()},
		{name: "crontask", got: NewCronTaskPlugin()},
		{name: "forwardshell", got: NewForwardShellPlugin()},
		{name: "keylogger", got: NewKeyloggerPlugin()},
		{name: "ldpreload", got: NewLDPreloadPlugin()},
		{name: "reverseshell", got: NewReverseShellPlugin()},
		{name: "socks5proxy", got: NewSocks5ProxyPlugin()},
		{name: "sshkey", got: NewSSHKeyPlugin()},
		{name: "systemdservice", got: NewSystemdServicePlugin()},
		{name: "systeminfo", got: NewSystemInfoPlugin()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got == nil {
				t.Fatal("constructor returned nil")
			}
			if got := tt.got.Name(); got != tt.name {
				t.Fatalf("Name() = %q, want %q", got, tt.name)
			}
		})
	}
}

func TestCronTaskScriptDetectionAndJobs(t *testing.T) {
	plugin := NewCronTaskPlugin()
	for _, name := range []string{"agent.sh", "agent.bash", "agent.zsh"} {
		plugin.targetFile = name
		if !plugin.isScriptFile() {
			t.Fatalf("%s should be treated as script", name)
		}
	}

	plugin.targetFile = "agent.bin"
	if plugin.isScriptFile() {
		t.Fatal("binary target should not be treated as script")
	}

	plugin.targetFile = "agent.sh"
	jobs := plugin.generateCronJobs("/tmp/agent.sh")
	if len(jobs) != 4 {
		t.Fatalf("job count = %d, want 4", len(jobs))
	}
	for _, job := range jobs {
		if !strings.Contains(job, "bash /tmp/agent.sh >/dev/null 2>&1") {
			t.Fatalf("script cron job missing bash wrapper: %q", job)
		}
	}
}

func TestLDPreloadValidFileDetection(t *testing.T) {
	dir := t.TempDir()
	plugin := NewLDPreloadPlugin()

	soPath := filepath.Join(dir, "libhook.so")
	if err := os.WriteFile(soPath, []byte("not actually elf"), 0600); err != nil {
		t.Fatal(err)
	}
	if !plugin.isValidFile(soPath) {
		t.Fatal(".so file should be accepted by extension")
	}

	elfPath := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(elfPath, []byte{0x7f, 'E', 'L', 'F', 0x02}, 0600); err != nil {
		t.Fatal(err)
	}
	if !plugin.isValidFile(elfPath) {
		t.Fatal("ELF magic file should be accepted")
	}

	textPath := filepath.Join(dir, "payload.txt")
	if err := os.WriteFile(textPath, []byte("plain text"), 0600); err != nil {
		t.Fatal(err)
	}
	if plugin.isValidFile(textPath) {
		t.Fatal("plain text file should not be accepted")
	}
}

func TestKeyloggerBufferAndFileHelpers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.log")
	session := common.NewScanSession(common.NewConfig(), common.NewState(), &common.FlagVars{})
	plugin := NewKeyloggerPlugin()

	if err := plugin.checkOutputFilePermissions(path); err != nil {
		t.Fatalf("checkOutputFilePermissions error = %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("output file was not created: %v", err)
	}

	if err := plugin.saveKeysToFile(path, session); err != nil {
		t.Fatalf("save empty keys error = %v", err)
	}

	plugin.addKeyToBuffer("A")
	plugin.addKeyToBuffer("B")
	if len(plugin.keyBuffer) != 2 {
		t.Fatalf("key buffer length = %d, want 2", len(plugin.keyBuffer))
	}
	if err := plugin.saveKeysToFile(path, session); err != nil {
		t.Fatalf("save keys error = %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "A") || !strings.Contains(string(content), "B") {
		t.Fatalf("saved key log missing entries: %q", content)
	}
}

func TestShellUtilityHelpers(t *testing.T) {
	prompt := NewForwardShellPlugin().getPrompt()
	if !strings.HasSuffix(prompt, "$ ") && !strings.HasSuffix(prompt, "> ") && !strings.HasSuffix(prompt, "# ") {
		t.Fatalf("unexpected prompt suffix: %q", prompt)
	}

	if dir := getCurrentDir(); dir == "" || dir == "unknown" {
		t.Fatalf("getCurrentDir() = %q", dir)
	}

	pub, priv, err := NewSSHKeyPlugin().generateKeyPair()
	if err != nil {
		t.Fatalf("generateKeyPair error = %v", err)
	}
	if !strings.HasPrefix(pub, "ssh-ed25519 ") {
		t.Fatalf("public key should be ssh-ed25519, got %q", pub)
	}
	if !strings.Contains(priv, "OPENSSH PRIVATE KEY") {
		t.Fatal("private key should be OpenSSH PEM")
	}
}
