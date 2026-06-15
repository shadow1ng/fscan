package lib

import (
	"testing"
	"unicode"

	"github.com/google/cel-go/common/types"
)

func TestRegisterRandomImplementations(t *testing.T) {
	overloads := registerRandomImplementations()

	idx := make(map[string]int, len(overloads))
	for i, o := range overloads {
		idx[o.Operator] = i
	}

	t.Run("randomInt_int_int", func(t *testing.T) {
		i, ok := idx["randomInt_int_int"]
		if !ok {
			t.Fatal("overload randomInt_int_int not found")
		}
		binary := overloads[i].Binary

		t.Run("returns_Int_type", func(t *testing.T) {
			result := binary(types.Int(0), types.Int(100))
			if types.IsError(result) {
				t.Fatalf("unexpected error: %v", result)
			}
			if _, ok := result.(types.Int); !ok {
				t.Errorf("expected types.Int, got %T", result)
			}
		})

		t.Run("value_in_range", func(t *testing.T) {
			min, max := types.Int(10), types.Int(20)
			for range 50 {
				result := binary(min, max)
				if types.IsError(result) {
					t.Fatalf("unexpected error: %v", result)
				}
				v := int64(result.(types.Int))
				if v < 10 || v >= 20 {
					t.Errorf("randomInt(10,20) = %d, out of [10,20)", v)
				}
			}
		})

		t.Run("max_le_min_returns_error", func(t *testing.T) {
			result := binary(types.Int(5), types.Int(5))
			if !types.IsError(result) {
				t.Errorf("expected error when max == min, got %v", result)
			}
		})

		t.Run("wrong_lhs_type", func(t *testing.T) {
			result := binary(types.String("x"), types.Int(10))
			if !types.IsError(result) {
				t.Error("expected error for non-Int lhs")
			}
		})

		t.Run("wrong_rhs_type", func(t *testing.T) {
			result := binary(types.Int(0), types.String("x"))
			if !types.IsError(result) {
				t.Error("expected error for non-Int rhs")
			}
		})
	})

	t.Run("randomLowercase_int", func(t *testing.T) {
		i, ok := idx["randomLowercase_int"]
		if !ok {
			t.Fatal("overload randomLowercase_int not found")
		}
		unary := overloads[i].Unary

		t.Run("returns_String_type", func(t *testing.T) {
			result := unary(types.Int(8))
			if types.IsError(result) {
				t.Fatalf("unexpected error: %v", result)
			}
			if _, ok := result.(types.String); !ok {
				t.Errorf("expected types.String, got %T", result)
			}
		})

		t.Run("correct_length", func(t *testing.T) {
			for _, n := range []int{0, 1, 8, 16} {
				result := unary(types.Int(n))
				if types.IsError(result) {
					t.Fatalf("unexpected error for n=%d: %v", n, result)
				}
				got := string(result.(types.String))
				if len(got) != n {
					t.Errorf("randomLowercase(%d) returned length %d", n, len(got))
				}
			}
		})

		t.Run("all_lowercase", func(t *testing.T) {
			result := unary(types.Int(32))
			got := string(result.(types.String))
			for _, r := range got {
				if !unicode.IsLower(r) {
					t.Errorf("randomLowercase returned non-lowercase char %q in %q", r, got)
				}
			}
		})

		t.Run("invalid_length_negative", func(t *testing.T) {
			result := unary(types.Int(-1))
			if !types.IsError(result) {
				t.Error("expected error for negative length")
			}
		})

		t.Run("invalid_length_too_large", func(t *testing.T) {
			result := unary(types.Int(maxRandomStringLength + 1))
			if !types.IsError(result) {
				t.Error("expected error for length > maxRandomStringLength")
			}
		})

		t.Run("wrong_type", func(t *testing.T) {
			result := unary(types.String("x"))
			if !types.IsError(result) {
				t.Error("expected error for non-Int input")
			}
		})
	})

	t.Run("randomUppercase_int", func(t *testing.T) {
		i, ok := idx["randomUppercase_int"]
		if !ok {
			t.Fatal("overload randomUppercase_int not found")
		}
		unary := overloads[i].Unary

		t.Run("returns_String_type", func(t *testing.T) {
			result := unary(types.Int(8))
			if types.IsError(result) {
				t.Fatalf("unexpected error: %v", result)
			}
			if _, ok := result.(types.String); !ok {
				t.Errorf("expected types.String, got %T", result)
			}
		})

		t.Run("correct_length", func(t *testing.T) {
			for _, n := range []int{0, 1, 8, 16} {
				result := unary(types.Int(n))
				if types.IsError(result) {
					t.Fatalf("unexpected error for n=%d: %v", n, result)
				}
				got := string(result.(types.String))
				if len(got) != n {
					t.Errorf("randomUppercase(%d) returned length %d", n, len(got))
				}
			}
		})

		t.Run("all_uppercase", func(t *testing.T) {
			result := unary(types.Int(32))
			got := string(result.(types.String))
			for _, r := range got {
				if !unicode.IsUpper(r) {
					t.Errorf("randomUppercase returned non-uppercase char %q in %q", r, got)
				}
			}
		})

		t.Run("wrong_type", func(t *testing.T) {
			result := unary(types.String("x"))
			if !types.IsError(result) {
				t.Error("expected error for non-Int input")
			}
		})
	})

	t.Run("randomString_int", func(t *testing.T) {
		i, ok := idx["randomString_int"]
		if !ok {
			t.Fatal("overload randomString_int not found")
		}
		unary := overloads[i].Unary

		t.Run("returns_String_type", func(t *testing.T) {
			result := unary(types.Int(8))
			if types.IsError(result) {
				t.Fatalf("unexpected error: %v", result)
			}
			if _, ok := result.(types.String); !ok {
				t.Errorf("expected types.String, got %T", result)
			}
		})

		t.Run("correct_length", func(t *testing.T) {
			for _, n := range []int{0, 1, 8, 16} {
				result := unary(types.Int(n))
				if types.IsError(result) {
					t.Fatalf("unexpected error for n=%d: %v", n, result)
				}
				got := string(result.(types.String))
				if len(got) != n {
					t.Errorf("randomString(%d) returned length %d", n, len(got))
				}
			}
		})

		t.Run("wrong_type", func(t *testing.T) {
			result := unary(types.String("x"))
			if !types.IsError(result) {
				t.Error("expected error for non-Int input")
			}
		})
	})
}

func TestRandomIntSpan(t *testing.T) {
	t.Run("normal_range", func(t *testing.T) {
		span, err := randomIntSpan(10, 20)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if span != 10 {
			t.Errorf("randomIntSpan(10,20) = %d, want 10", span)
		}
	})

	t.Run("min_zero", func(t *testing.T) {
		span, err := randomIntSpan(0, 100)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if span != 100 {
			t.Errorf("randomIntSpan(0,100) = %d, want 100", span)
		}
	})

	t.Run("negative_min", func(t *testing.T) {
		span, err := randomIntSpan(-5, 5)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if span != 10 {
			t.Errorf("randomIntSpan(-5,5) = %d, want 10", span)
		}
	})

	t.Run("max_eq_min_returns_error", func(t *testing.T) {
		_, err := randomIntSpan(7, 7)
		if err == nil {
			t.Error("expected error when max == min")
		}
	})

	t.Run("max_lt_min_returns_error", func(t *testing.T) {
		_, err := randomIntSpan(10, 5)
		if err == nil {
			t.Error("expected error when max < min")
		}
	})
}
