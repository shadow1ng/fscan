package lib

import (
	"testing"

	"github.com/google/cel-go/common/types"
)

func TestRegisterEncodingImplementations(t *testing.T) {
	overloads := registerEncodingImplementations()

	idx := make(map[string]int, len(overloads))
	for i, o := range overloads {
		idx[o.Operator] = i
	}

	t.Run("base64_string", func(t *testing.T) {
		unary := overloads[idx["base64_string"]].Unary

		tests := []struct {
			input types.String
			want  types.String
		}{
			{"hello", "aGVsbG8="},
			{"", ""},
			{"hello world", "aGVsbG8gd29ybGQ="},
		}
		for _, tc := range tests {
			result := unary(tc.input)
			if types.IsError(result) {
				t.Fatalf("base64_string(%q): unexpected error %v", tc.input, result)
			}
			got, ok := result.(types.String)
			if !ok {
				t.Fatalf("expected types.String, got %T", result)
			}
			if got != tc.want {
				t.Errorf("base64_string(%q) = %q, want %q", tc.input, got, tc.want)
			}
		}
	})

	t.Run("base64_string_wrong_type", func(t *testing.T) {
		result := overloads[idx["base64_string"]].Unary(types.Int(1))
		if !types.IsError(result) {
			t.Error("expected error for non-String input")
		}
	})

	t.Run("base64_bytes", func(t *testing.T) {
		unary := overloads[idx["base64_bytes"]].Unary

		tests := []struct {
			input types.Bytes
			want  types.String
		}{
			{types.Bytes([]byte("hello")), "aGVsbG8="},
			{types.Bytes([]byte{}), ""},
		}
		for _, tc := range tests {
			result := unary(tc.input)
			if types.IsError(result) {
				t.Fatalf("base64_bytes: unexpected error %v", result)
			}
			got, ok := result.(types.String)
			if !ok {
				t.Fatalf("expected types.String, got %T", result)
			}
			if got != tc.want {
				t.Errorf("base64_bytes(%v) = %q, want %q", []byte(tc.input), got, tc.want)
			}
		}
	})

	t.Run("base64_bytes_wrong_type", func(t *testing.T) {
		result := overloads[idx["base64_bytes"]].Unary(types.String("hello"))
		if !types.IsError(result) {
			t.Error("expected error for non-Bytes input")
		}
	})

	t.Run("base64Decode_string", func(t *testing.T) {
		unary := overloads[idx["base64Decode_string"]].Unary

		tests := []struct {
			input types.String
			want  types.String
		}{
			{"aGVsbG8=", "hello"},
			{"", ""},
			{"aGVsbG8gd29ybGQ=", "hello world"},
		}
		for _, tc := range tests {
			result := unary(tc.input)
			if types.IsError(result) {
				t.Fatalf("base64Decode_string(%q): unexpected error %v", tc.input, result)
			}
			got, ok := result.(types.String)
			if !ok {
				t.Fatalf("expected types.String, got %T", result)
			}
			if got != tc.want {
				t.Errorf("base64Decode_string(%q) = %q, want %q", tc.input, got, tc.want)
			}
		}
	})

	t.Run("base64Decode_string_invalid", func(t *testing.T) {
		result := overloads[idx["base64Decode_string"]].Unary(types.String("!!!"))
		if !types.IsError(result) {
			t.Error("expected error for invalid base64 input")
		}
	})

	t.Run("base64Decode_string_wrong_type", func(t *testing.T) {
		result := overloads[idx["base64Decode_string"]].Unary(types.Bool(true))
		if !types.IsError(result) {
			t.Error("expected error for non-String input")
		}
	})

	t.Run("base64Decode_bytes", func(t *testing.T) {
		unary := overloads[idx["base64Decode_bytes"]].Unary

		result := unary(types.Bytes([]byte("aGVsbG8=")))
		if types.IsError(result) {
			t.Fatalf("unexpected error: %v", result)
		}
		got, ok := result.(types.String)
		if !ok {
			t.Fatalf("expected types.String, got %T", result)
		}
		if got != "hello" {
			t.Errorf("base64Decode_bytes = %q, want %q", got, "hello")
		}
	})

	t.Run("base64Decode_bytes_invalid", func(t *testing.T) {
		result := overloads[idx["base64Decode_bytes"]].Unary(types.Bytes([]byte("!!!")))
		if !types.IsError(result) {
			t.Error("expected error for invalid base64 bytes")
		}
	})

	t.Run("urlencode_string", func(t *testing.T) {
		unary := overloads[idx["urlencode_string"]].Unary

		// url.QueryEscape: 空格 → "+"
		tests := []struct {
			input types.String
			want  types.String
		}{
			{"hello world", "hello+world"},
			{"a=1&b=2", "a%3D1%26b%3D2"},
			{"", ""},
		}
		for _, tc := range tests {
			result := unary(tc.input)
			if types.IsError(result) {
				t.Fatalf("urlencode_string(%q): unexpected error %v", tc.input, result)
			}
			got, ok := result.(types.String)
			if !ok {
				t.Fatalf("expected types.String, got %T", result)
			}
			if got != tc.want {
				t.Errorf("urlencode_string(%q) = %q, want %q", tc.input, got, tc.want)
			}
		}
	})

	t.Run("urlencode_string_wrong_type", func(t *testing.T) {
		result := overloads[idx["urlencode_string"]].Unary(types.Int(0))
		if !types.IsError(result) {
			t.Error("expected error for non-String input")
		}
	})

	t.Run("urldecode_string", func(t *testing.T) {
		unary := overloads[idx["urldecode_string"]].Unary

		tests := []struct {
			input types.String
			want  types.String
		}{
			{"hello%20world", "hello world"},
			{"hello+world", "hello world"},
			{"", ""},
		}
		for _, tc := range tests {
			result := unary(tc.input)
			if types.IsError(result) {
				t.Fatalf("urldecode_string(%q): unexpected error %v", tc.input, result)
			}
			got, ok := result.(types.String)
			if !ok {
				t.Fatalf("expected types.String, got %T", result)
			}
			if got != tc.want {
				t.Errorf("urldecode_string(%q) = %q, want %q", tc.input, got, tc.want)
			}
		}
	})

	t.Run("urldecode_string_invalid", func(t *testing.T) {
		// % 后跟非法字符
		result := overloads[idx["urldecode_string"]].Unary(types.String("hello%ZZ"))
		if !types.IsError(result) {
			t.Error("expected error for invalid percent-encoding")
		}
	})

	t.Run("urldecode_string_wrong_type", func(t *testing.T) {
		result := overloads[idx["urldecode_string"]].Unary(types.Bool(false))
		if !types.IsError(result) {
			t.Error("expected error for non-String input")
		}
	})

	t.Run("hexdecode", func(t *testing.T) {
		unary := overloads[idx["hexdecode"]].Unary

		tests := []struct {
			input types.String
			want  []byte
		}{
			{"48656c6c6f", []byte("Hello")},
			{"", []byte{}},
			{"deadbeef", []byte{0xde, 0xad, 0xbe, 0xef}},
		}
		for _, tc := range tests {
			result := unary(tc.input)
			if types.IsError(result) {
				t.Fatalf("hexdecode(%q): unexpected error %v", tc.input, result)
			}
			got, ok := result.(types.Bytes)
			if !ok {
				t.Fatalf("expected types.Bytes, got %T", result)
			}
			if string(got) != string(tc.want) {
				t.Errorf("hexdecode(%q) = %v, want %v", tc.input, []byte(got), tc.want)
			}
		}
	})

	t.Run("hexdecode_invalid", func(t *testing.T) {
		result := overloads[idx["hexdecode"]].Unary(types.String("zz"))
		if !types.IsError(result) {
			t.Error("expected error for invalid hex input")
		}
	})

	t.Run("hexdecode_wrong_type", func(t *testing.T) {
		result := overloads[idx["hexdecode"]].Unary(types.Int(99))
		if !types.IsError(result) {
			t.Error("expected error for non-String input")
		}
	})
}
