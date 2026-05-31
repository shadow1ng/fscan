package common

import (
	"reflect"
	"testing"
)

func TestNormalizeMultiValueFlagArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "space separated pwda values",
			args: []string{"-h", "192.168.1.1", "-pwda", "pass1", "pass2", "pass3", "-m", "ssh"},
			want: []string{"-h", "192.168.1.1", "-pwda", "pass1,pass2,pass3", "-m", "ssh"},
		},
		{
			name: "equals form with extra values",
			args: []string{"-pwda=pass1", "pass2", "-h", "192.168.1.1"},
			want: []string{"-pwda=pass1,pass2", "-h", "192.168.1.1"},
		},
		{
			name: "unrelated args unchanged",
			args: []string{"-h", "192.168.1.1", "-m", "ssh"},
			want: []string{"-h", "192.168.1.1", "-m", "ssh"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeMultiValueFlagArgs(tt.args, "-pwda")
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("normalizeMultiValueFlagArgs() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
