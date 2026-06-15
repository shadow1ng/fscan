package lib

import (
	"testing"

	"gopkg.in/yaml.v2"
)

// =============================================================================
// UnmarshalYAML 测试
// =============================================================================

func TestStrMapUnmarshalYAML(t *testing.T) {
	t.Run("正常键值对", func(t *testing.T) {
		data := []byte("key1: val1\nkey2: val2\n")
		var m StrMap
		if err := yaml.Unmarshal(data, &m); err != nil {
			t.Fatalf("yaml.Unmarshal error = %v", err)
		}
		if len(m) != 2 {
			t.Fatalf("len = %d, want 2", len(m))
		}
		if m[0].Key != "key1" || m[0].Value != "val1" {
			t.Errorf("m[0] = %+v, want {key1 val1}", m[0])
		}
		if m[1].Key != "key2" || m[1].Value != "val2" {
			t.Errorf("m[1] = %+v, want {key2 val2}", m[1])
		}
	})

	t.Run("单项", func(t *testing.T) {
		data := []byte("only: one\n")
		var m StrMap
		if err := yaml.Unmarshal(data, &m); err != nil {
			t.Fatalf("yaml.Unmarshal error = %v", err)
		}
		if len(m) != 1 || m[0].Key != "only" || m[0].Value != "one" {
			t.Fatalf("m = %+v", m)
		}
	})

	t.Run("randomInt 值保留为字符串", func(t *testing.T) {
		data := []byte("port: randomInt(1000, 9000)\n")
		var m StrMap
		if err := yaml.Unmarshal(data, &m); err != nil {
			t.Fatalf("yaml.Unmarshal error = %v", err)
		}
		if len(m) != 1 || m[0].Value != "randomInt(1000, 9000)" {
			t.Fatalf("m = %+v", m)
		}
	})
}

func TestListMapUnmarshalYAML(t *testing.T) {
	t.Run("正常列表值", func(t *testing.T) {
		data := []byte("users:\n  - admin\n  - root\npasses:\n  - 123\n  - 456\n")
		var m ListMap
		if err := yaml.Unmarshal(data, &m); err != nil {
			t.Fatalf("yaml.Unmarshal error = %v", err)
		}
		if len(m) != 2 {
			t.Fatalf("len = %d, want 2", len(m))
		}
		if m[0].Key != "users" || len(m[0].Value) != 2 || m[0].Value[0] != "admin" || m[0].Value[1] != "root" {
			t.Errorf("m[0] = %+v", m[0])
		}
		if m[1].Key != "passes" || len(m[1].Value) != 2 || m[1].Value[0] != "123" || m[1].Value[1] != "456" {
			t.Errorf("m[1] = %+v", m[1])
		}
	})

	t.Run("单个列表", func(t *testing.T) {
		data := []byte("cmd:\n  - whoami\n")
		var m ListMap
		if err := yaml.Unmarshal(data, &m); err != nil {
			t.Fatalf("yaml.Unmarshal error = %v", err)
		}
		if len(m) != 1 || m[0].Key != "cmd" || m[0].Value[0] != "whoami" {
			t.Fatalf("m = %+v", m)
		}
	})

	t.Run("数字值转字符串", func(t *testing.T) {
		data := []byte("ports:\n  - 80\n  - 443\n")
		var m ListMap
		if err := yaml.Unmarshal(data, &m); err != nil {
			t.Fatalf("yaml.Unmarshal error = %v", err)
		}
		if m[0].Value[0] != "80" || m[0].Value[1] != "443" {
			t.Errorf("数字未转为字符串: %+v", m[0].Value)
		}
	})
}

func TestStrMapUnmarshalYAML_InvalidValue(t *testing.T) {
	// value 是嵌套 map，不是字符串，应报错
	data := []byte("key:\n  nested: val\n")
	var m StrMap
	if err := yaml.Unmarshal(data, &m); err == nil {
		t.Fatal("期望错误，实际 nil")
	}
}

func TestListMapUnmarshalYAML_InvalidValue(t *testing.T) {
	// value 是普通字符串而非列表，应报错
	data := []byte("key: notalist\n")
	var m ListMap
	if err := yaml.Unmarshal(data, &m); err == nil {
		t.Fatal("期望错误，实际 nil")
	}
}

func TestNormalizeHTTPProxyURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "port shortcut", in: "8080", want: "http://127.0.0.1:8080"},
		{name: "ipv4 host port", in: "127.0.0.1:8080", want: "http://127.0.0.1:8080"},
		{name: "hostname port", in: "proxy.local:8080", want: "http://proxy.local:8080"},
		{name: "bracketed ipv6 port", in: "[::1]:8080", want: "http://[::1]:8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeHTTPProxyURL(tt.in); got != tt.want {
				t.Fatalf("normalizeHTTPProxyURL(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
