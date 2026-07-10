package lib

import (
	"sync"
	"testing"
)

func TestPocPreparePrecompilesAndReusesPlan(t *testing.T) {
	poc := &Poc{
		Name: "prepared-test",
		Set: StrMap{
			{Key: "token", Value: `"ok"`},
		},
		Rules: []Rules{
			{
				Search:     `user=(?P<username>[a-z]+)`,
				Expression: `token == "ok"`,
			},
			{
				Expression: `username == "admin"`,
			},
		},
	}

	if err := poc.Prepare(); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	first := poc.prepared
	if first == nil || first.env == nil || first.programs == nil {
		t.Fatal("Prepare() did not create a complete execution plan")
	}
	if got, want := first.programs.len(), 3; got != want {
		t.Fatalf("compiled program count = %d, want %d", got, want)
	}
	if got := first.search(`user=(?P<username>[a-z]+)`, "user=admin"); got["username"] != "admin" {
		t.Fatalf("precompiled search result = %#v", got)
	}

	if err := poc.Prepare(); err != nil {
		t.Fatalf("second Prepare() error = %v", err)
	}
	if poc.prepared != first {
		t.Fatal("Prepare() rebuilt an already prepared POC")
	}
}

func TestPocPrepareConcurrentEvaluation(t *testing.T) {
	poc := &Poc{
		Set:   StrMap{{Key: "token", Value: `"ok"`}},
		Rules: []Rules{{Expression: `token == "ok"`}},
	}
	if err := poc.Prepare(); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	const workers = 32
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := EvaluateCached(poc.prepared.env, `token == "ok"`, map[string]interface{}{"token": "ok"}, poc.prepared.programs)
			if err != nil {
				errs <- err
				return
			}
			if value, ok := out.Value().(bool); !ok || !value {
				errs <- errUnexpectedPreparedResult
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent evaluation error = %v", err)
		}
	}
}

func TestPocPrepareCachesInvalidCEL(t *testing.T) {
	poc := &Poc{Rules: []Rules{{Expression: "response."}}}
	if err := poc.Prepare(); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	program, compileErr, cached := poc.prepared.programs.get("response.")
	if !cached || compileErr == nil || program != nil {
		t.Fatalf("invalid CEL cache = (program=%v, err=%v, cached=%v)", program, compileErr, cached)
	}
}

func TestPocPrepareRejectsInvalidSearchRegex(t *testing.T) {
	poc := &Poc{Rules: []Rules{{Search: "[", Expression: "true"}}}
	if err := poc.Prepare(); err == nil {
		t.Fatal("Prepare() error = nil, want regex validation error")
	}
}

func BenchmarkPocCELEvaluation(b *testing.B) {
	poc := &Poc{
		Set:   StrMap{{Key: "token", Value: `"ok"`}},
		Rules: []Rules{{Expression: `token == "ok" && response.status == 200`}},
	}
	if err := poc.Prepare(); err != nil {
		b.Fatalf("Prepare() error = %v", err)
	}
	params := map[string]interface{}{
		"token":    "ok",
		"response": &Response{Status: 200},
	}
	expression := poc.Rules[0].Expression

	b.Run("prepared", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := EvaluateCached(poc.prepared.env, expression, params, poc.prepared.programs); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("compile-each-time", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := Evaluate(poc.prepared.env, expression, params); err != nil {
				b.Fatal(err)
			}
		}
	})
}

type preparedResultError string

func (e preparedResultError) Error() string { return string(e) }

const errUnexpectedPreparedResult preparedResultError = "prepared CEL program returned a non-true result"
