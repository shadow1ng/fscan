package lib

import (
	"testing"
	"unicode"

	"github.com/google/cel-go/common/types"
)

func TestRegisterMiscImplementations_TongdaDate(t *testing.T) {
	overloads := registerMiscImplementations()

	idx := make(map[string]int, len(overloads))
	for i, o := range overloads {
		idx[o.Operator] = i
	}

	i, ok := idx["tongda_date"]
	if !ok {
		t.Fatal("overload tongda_date not found")
	}
	fn := overloads[i].Function
	if fn == nil {
		t.Fatal("tongda_date Function field is nil")
	}

	result := fn()

	if types.IsError(result) {
		t.Fatalf("unexpected error: %v", result)
	}

	got, ok := result.(types.String)
	if !ok {
		t.Fatalf("expected types.String, got %T", result)
	}

	s := string(got)

	t.Run("length_is_4", func(t *testing.T) {
		if len(s) != 4 {
			t.Errorf("tongda_date returned %q, want 4-char string", s)
		}
	})

	t.Run("all_digits", func(t *testing.T) {
		for _, r := range s {
			if !unicode.IsDigit(r) {
				t.Errorf("tongda_date returned %q, contains non-digit char %q", s, r)
			}
		}
	})
}
