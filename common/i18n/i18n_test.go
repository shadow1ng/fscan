package i18n

import (
	"strings"
	"testing"
)

func TestLanguageLifecycleAndFallbacks(t *testing.T) {
	original := GetLanguage()
	t.Cleanup(func() { SetLanguage(original) })

	SetLanguage(LangEN)
	if got := GetLanguage(); got != LangEN {
		t.Fatalf("language = %q, want %q", got, LangEN)
	}
	if got := GetText("concurrency_plugin"); got == "" || got == "concurrency_plugin" {
		t.Fatalf("english text = %q, want translated text", got)
	}
	if got := Tr("debug_cpu_profile_started", "/tmp/profiles"); !strings.Contains(got, "/tmp/profiles") {
		t.Fatalf("formatted english text = %q, want path included", got)
	}

	SetLanguage(LangZH)
	if got := GetLanguage(); got != LangZH {
		t.Fatalf("language = %q, want %q", got, LangZH)
	}
	if got := GetText("concurrency_plugin"); got == "" || got == "concurrency_plugin" {
		t.Fatalf("chinese text = %q, want translated text", got)
	}

	if got := GetText("missing_translation_key"); got != "missing_translation_key" {
		t.Fatalf("missing GetText = %q, want key", got)
	}
	if got := Tr("missing_translation_key", "ignored"); got != "missing_translation_key" {
		t.Fatalf("missing Tr = %q, want key", got)
	}
}
