package core

import (
	"os"
	"reflect"
	"testing"

	"github.com/shadow1ng/fscan/common"
)

func TestLoadHostExcludesIncludesExcludeFile(t *testing.T) {
	path := t.TempDir() + "/exclude.txt"
	if err := os.WriteFile(path, []byte("192.168.1.2\n# comment\n192.168.1.3\n"), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	got, err := loadHostExcludes(&common.FlagVars{
		ExcludeHosts:     "192.168.1.1",
		ExcludeHostsFile: path,
	})
	if err != nil {
		t.Fatalf("loadHostExcludes error = %v", err)
	}

	want := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loadHostExcludes = %#v, want %#v", got, want)
	}
}
