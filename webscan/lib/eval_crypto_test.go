package lib

import (
	"testing"

	"github.com/google/cel-go/common/types"
)

func TestRegisterCryptoImplementations(t *testing.T) {
	overloads := registerCryptoImplementations()

	// 建立 operator → index 映射
	idx := make(map[string]int, len(overloads))
	for i, o := range overloads {
		idx[o.Operator] = i
	}

	t.Run("md5_string", func(t *testing.T) {
		i, ok := idx["md5_string"]
		if !ok {
			t.Fatal("overload md5_string not found")
		}
		unary := overloads[i].Unary

		tests := []struct {
			name    string
			input   types.String
			want    types.String
			wantErr bool
		}{
			{"hello", "hello", "5d41402abc4b2a76b9719d911017c592", false},
			{"empty", "", "d41d8cd98f00b204e9800998ecf8427e", false},
			{"abc", "abc", "900150983cd24fb0d6963f7d28e17f72", false},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				result := unary(tc.input)
				if types.IsError(result) {
					t.Fatalf("unexpected error: %v", result)
				}
				got, ok := result.(types.String)
				if !ok {
					t.Fatalf("expected types.String, got %T", result)
				}
				if got != tc.want {
					t.Errorf("md5(%q) = %q, want %q", tc.input, got, tc.want)
				}
			})
		}
	})

	t.Run("md5_string_wrong_type", func(t *testing.T) {
		i := idx["md5_string"]
		result := overloads[i].Unary(types.Int(42))
		if !types.IsError(result) {
			t.Errorf("expected error for non-String input, got %v", result)
		}
	})

	t.Run("shiro_key_valid", func(t *testing.T) {
		i, ok := idx["shiro_key"]
		if !ok {
			t.Fatal("overload shiro_key not found")
		}
		binary := overloads[i].Binary

		// kPH+bIxk5D2deZiIxcaaaA== 是常见 shiro 默认 key
		result := binary(types.String("kPH+bIxk5D2deZiIxcaaaA=="), types.String("cbc"))
		if types.IsError(result) {
			t.Fatalf("unexpected error: %v", result)
		}
		got, ok := result.(types.String)
		if !ok {
			t.Fatalf("expected types.String, got %T", result)
		}
		if got == "" {
			t.Error("shiro_key returned empty string")
		}
	})

	t.Run("shiro_key_invalid_base64", func(t *testing.T) {
		i := idx["shiro_key"]
		binary := overloads[i].Binary

		// 无效 base64，GetShrioCookie 会返回 ""，函数返回 NewErr
		result := binary(types.String("!!!not_valid_base64!!!"), types.String("cbc"))
		if !types.IsError(result) {
			t.Errorf("expected error for invalid base64 key, got %v", result)
		}
	})

	t.Run("shiro_key_wrong_key_type", func(t *testing.T) {
		i := idx["shiro_key"]
		result := overloads[i].Binary(types.Int(1), types.String("cbc"))
		if !types.IsError(result) {
			t.Error("expected error for non-String key")
		}
	})

	t.Run("shiro_key_wrong_mode_type", func(t *testing.T) {
		i := idx["shiro_key"]
		result := overloads[i].Binary(types.String("kPH+bIxk5D2deZiIxcaaaA=="), types.Int(0))
		if !types.IsError(result) {
			t.Error("expected error for non-String mode")
		}
	})
}
