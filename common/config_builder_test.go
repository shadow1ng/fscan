package common

import (
	"reflect"
	"testing"
)

func TestParsePasswordsSplitsCommaAndWhitespace(t *testing.T) {
	fv := &FlagVars{
		Password:     "root,admin",
		AddPasswords: "pass1 pass2,pass3\tpass4",
	}

	got := parsePasswords(fv)
	want := []string{"root", "admin", "pass1", "pass2", "pass3", "pass4"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsePasswords() = %#v, want %#v", got, want)
	}
}
