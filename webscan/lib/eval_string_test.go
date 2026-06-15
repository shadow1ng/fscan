package lib

import (
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

func TestRegisterStringImplementations(t *testing.T) {
	overloads := registerStringImplementations()

	idx := make(map[string]int, len(overloads))
	for i, o := range overloads {
		idx[o.Operator] = i
	}

	t.Run("bytes_bcontains_bytes", func(t *testing.T) {
		binary := overloads[idx["bytes_bcontains_bytes"]].Binary

		tests := []struct {
			name string
			lhs  types.Bytes
			rhs  types.Bytes
			want types.Bool
		}{
			{"contains", types.Bytes([]byte("hello world")), types.Bytes([]byte("world")), true},
			{"not_contains", types.Bytes([]byte("hello world")), types.Bytes([]byte("xyz")), false},
			{"empty_needle", types.Bytes([]byte("hello")), types.Bytes([]byte{}), true},
			{"both_empty", types.Bytes([]byte{}), types.Bytes([]byte{}), true},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				result := binary(tc.lhs, tc.rhs)
				if types.IsError(result) {
					t.Fatalf("unexpected error: %v", result)
				}
				got, ok := result.(types.Bool)
				if !ok {
					t.Fatalf("expected types.Bool, got %T", result)
				}
				if got != tc.want {
					t.Errorf("bcontains = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("bytes_bcontains_bytes_wrong_lhs", func(t *testing.T) {
		result := overloads[idx["bytes_bcontains_bytes"]].Binary(types.String("hello"), types.Bytes([]byte("x")))
		if !types.IsError(result) {
			t.Error("expected error for non-Bytes lhs")
		}
	})

	t.Run("bytes_bcontains_bytes_wrong_rhs", func(t *testing.T) {
		result := overloads[idx["bytes_bcontains_bytes"]].Binary(types.Bytes([]byte("hello")), types.String("x"))
		if !types.IsError(result) {
			t.Error("expected error for non-Bytes rhs")
		}
	})

	t.Run("string_bmatches_bytes", func(t *testing.T) {
		binary := overloads[idx["string_bmatches_bytes"]].Binary

		tests := []struct {
			name    string
			pattern types.String
			input   types.Bytes
			want    types.Bool
		}{
			{"digits_match", `\d+`, types.Bytes([]byte("abc123")), true},
			{"digits_no_match", `\d+`, types.Bytes([]byte("abc")), false},
			{"any", `.*`, types.Bytes([]byte("hello")), true},
			{"empty_pattern", ``, types.Bytes([]byte("hello")), true},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				result := binary(tc.pattern, tc.input)
				if types.IsError(result) {
					t.Fatalf("unexpected error: %v", result)
				}
				got, ok := result.(types.Bool)
				if !ok {
					t.Fatalf("expected types.Bool, got %T", result)
				}
				if got != tc.want {
					t.Errorf("bmatches(%q, %q) = %v, want %v", tc.pattern, tc.input, got, tc.want)
				}
			})
		}
	})

	t.Run("string_bmatches_bytes_invalid_regex", func(t *testing.T) {
		result := overloads[idx["string_bmatches_bytes"]].Binary(types.String(`[invalid`), types.Bytes([]byte("hello")))
		if !types.IsError(result) {
			t.Error("expected error for invalid regex pattern")
		}
	})

	t.Run("string_bmatches_bytes_wrong_lhs", func(t *testing.T) {
		result := overloads[idx["string_bmatches_bytes"]].Binary(types.Int(0), types.Bytes([]byte("hello")))
		if !types.IsError(result) {
			t.Error("expected error for non-String lhs")
		}
	})

	t.Run("string_bmatches_bytes_wrong_rhs", func(t *testing.T) {
		result := overloads[idx["string_bmatches_bytes"]].Binary(types.String(`\d+`), types.String("123"))
		if !types.IsError(result) {
			t.Error("expected error for non-Bytes rhs")
		}
	})

	t.Run("icontains_string", func(t *testing.T) {
		binary := overloads[idx["icontains_string"]].Binary

		tests := []struct {
			name string
			lhs  types.String
			rhs  types.String
			want types.Bool
		}{
			{"case_insensitive_match", "Hello World", "hello", true},
			{"exact_match", "Hello World", "Hello", true},
			{"upper_needle", "hello world", "WORLD", true},
			{"not_contains", "hello world", "xyz", false},
			{"empty_needle", "hello", "", true},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				result := binary(tc.lhs, tc.rhs)
				if types.IsError(result) {
					t.Fatalf("unexpected error: %v", result)
				}
				got, ok := result.(types.Bool)
				if !ok {
					t.Fatalf("expected types.Bool, got %T", result)
				}
				if got != tc.want {
					t.Errorf("icontains(%q, %q) = %v, want %v", tc.lhs, tc.rhs, got, tc.want)
				}
			})
		}
	})

	t.Run("icontains_string_wrong_lhs", func(t *testing.T) {
		result := overloads[idx["icontains_string"]].Binary(types.Bool(true), types.String("x"))
		if !types.IsError(result) {
			t.Error("expected error for non-String lhs")
		}
	})

	t.Run("icontains_string_wrong_rhs", func(t *testing.T) {
		result := overloads[idx["icontains_string"]].Binary(types.String("hello"), types.Int(1))
		if !types.IsError(result) {
			t.Error("expected error for non-String rhs")
		}
	})

	t.Run("substr_string_int_int", func(t *testing.T) {
		fn := overloads[idx["substr_string_int_int"]].Function

		tests := []struct {
			name   string
			str    types.String
			start  types.Int
			length types.Int
			want   types.String
		}{
			{"basic", "hello world", 0, 5, "hello"},
			{"middle", "hello world", 6, 5, "world"},
			{"single_char", "hello", 1, 1, "e"},
			{"full", "hello", 0, 5, "hello"},
			{"zero_length", "hello", 2, 0, ""},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				result := fn(tc.str, tc.start, tc.length)
				if types.IsError(result) {
					t.Fatalf("substr(%q, %d, %d): unexpected error %v", tc.str, tc.start, tc.length, result)
				}
				got, ok := result.(types.String)
				if !ok {
					t.Fatalf("expected types.String, got %T", result)
				}
				if got != tc.want {
					t.Errorf("substr(%q, %d, %d) = %q, want %q", tc.str, tc.start, tc.length, got, tc.want)
				}
			})
		}
	})

	t.Run("substr_out_of_bounds", func(t *testing.T) {
		fn := overloads[idx["substr_string_int_int"]].Function

		oob := []struct {
			name   string
			str    types.String
			start  types.Int
			length types.Int
		}{
			{"negative_start", "hello", -1, 2},
			{"negative_length", "hello", 0, -1},
			{"start_too_large", "hello", 10, 1},
			{"length_overflow", "hello", 3, 10},
		}
		for _, tc := range oob {
			t.Run(tc.name, func(t *testing.T) {
				result := fn(tc.str, tc.start, tc.length)
				if !types.IsError(result) {
					t.Errorf("expected error for substr(%q, %d, %d), got %v", tc.str, tc.start, tc.length, result)
				}
			})
		}
	})

	t.Run("substr_wrong_arg_count", func(t *testing.T) {
		fn := overloads[idx["substr_string_int_int"]].Function
		result := fn(types.String("hello"), types.Int(0))
		if !types.IsError(result) {
			t.Error("expected error for wrong argument count")
		}
	})

	t.Run("substr_wrong_types", func(t *testing.T) {
		fn := overloads[idx["substr_string_int_int"]].Function

		cases := []struct {
			name string
			args []ref.Val
		}{
			{"wrong_str", []ref.Val{types.Int(0), types.Int(0), types.Int(1)}},
			{"wrong_start", []ref.Val{types.String("hello"), types.String("x"), types.Int(1)}},
			{"wrong_length", []ref.Val{types.String("hello"), types.Int(0), types.String("x")}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				result := fn(tc.args...)
				if !types.IsError(result) {
					t.Errorf("expected error, got %v", result)
				}
			})
		}
	})

	t.Run("startsWith_bytes", func(t *testing.T) {
		binary := overloads[idx["startsWith_bytes"]].Binary

		tests := []struct {
			name string
			lhs  types.Bytes
			rhs  types.Bytes
			want types.Bool
		}{
			{"match", types.Bytes([]byte("hello world")), types.Bytes([]byte("hello")), true},
			{"no_match", types.Bytes([]byte("hello world")), types.Bytes([]byte("world")), false},
			{"empty_prefix", types.Bytes([]byte("hello")), types.Bytes([]byte{}), true},
			{"exact", types.Bytes([]byte("hello")), types.Bytes([]byte("hello")), true},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				result := binary(tc.lhs, tc.rhs)
				if types.IsError(result) {
					t.Fatalf("unexpected error: %v", result)
				}
				got, ok := result.(types.Bool)
				if !ok {
					t.Fatalf("expected types.Bool, got %T", result)
				}
				if got != tc.want {
					t.Errorf("startsWith_bytes = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("startsWith_bytes_wrong_lhs", func(t *testing.T) {
		result := overloads[idx["startsWith_bytes"]].Binary(types.String("hello"), types.Bytes([]byte("h")))
		if !types.IsError(result) {
			t.Error("expected error for non-Bytes lhs")
		}
	})

	t.Run("startsWith_bytes_wrong_rhs", func(t *testing.T) {
		result := overloads[idx["startsWith_bytes"]].Binary(types.Bytes([]byte("hello")), types.String("h"))
		if !types.IsError(result) {
			t.Error("expected error for non-Bytes rhs")
		}
	})

	t.Run("startsWith_string", func(t *testing.T) {
		binary := overloads[idx["startsWith_string"]].Binary

		tests := []struct {
			name string
			lhs  types.String
			rhs  types.String
			want types.Bool
		}{
			{"case_insensitive_match", "Hello World", "hello", true},
			{"upper_prefix", "hello world", "HELLO", true},
			{"no_match", "hello world", "world", false},
			{"empty_prefix", "hello", "", true},
			{"exact", "Hello", "Hello", true},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				result := binary(tc.lhs, tc.rhs)
				if types.IsError(result) {
					t.Fatalf("unexpected error: %v", result)
				}
				got, ok := result.(types.Bool)
				if !ok {
					t.Fatalf("expected types.Bool, got %T", result)
				}
				if got != tc.want {
					t.Errorf("startsWith_string(%q, %q) = %v, want %v", tc.lhs, tc.rhs, got, tc.want)
				}
			})
		}
	})

	t.Run("startsWith_string_wrong_lhs", func(t *testing.T) {
		result := overloads[idx["startsWith_string"]].Binary(types.Int(0), types.String("h"))
		if !types.IsError(result) {
			t.Error("expected error for non-String lhs")
		}
	})

	t.Run("startsWith_string_wrong_rhs", func(t *testing.T) {
		result := overloads[idx["startsWith_string"]].Binary(types.String("hello"), types.Bool(true))
		if !types.IsError(result) {
			t.Error("expected error for non-String rhs")
		}
	})
}
