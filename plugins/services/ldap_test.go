//go:build plugin_ldap || !plugin_selective

package services

import (
	"errors"
	"fmt"
	"testing"

	ldaplib "github.com/go-ldap/ldap/v3"
)

func TestLDAPDNFormatsEscapeUsernameValue(t *testing.T) {
	username := "admin,ou=evil"
	escapedUser := ldaplib.EscapeDN(username)
	got := []string{
		fmt.Sprintf("cn=%s,dc=example,dc=com", escapedUser),
		fmt.Sprintf("uid=%s,dc=example,dc=com", escapedUser),
		fmt.Sprintf("cn=%s,ou=users,dc=example,dc=com", escapedUser),
		username,
	}

	for _, dn := range got[:3] {
		if dn == "cn=admin,ou=evil,dc=example,dc=com" || dn == "uid=admin,ou=evil,dc=example,dc=com" {
			t.Fatalf("DN was not escaped: %q", dn)
		}
	}
	if got[0] != `cn=admin\,ou=evil,dc=example,dc=com` {
		t.Fatalf("escaped DN = %q", got[0])
	}
}

func TestClassifyLDAPErrorType(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorType
	}{
		{"nil", nil, ErrorTypeUnknown},
		{"invalid credentials", errors.New("invalid credentials"), ErrorTypeAuth},
		{"bind failed", errors.New("bind failed"), ErrorTypeAuth},
		{"ldap connection lost", errors.New("ldap: connection lost"), ErrorTypeNetwork},
		{"connection refused", errors.New("connection refused"), ErrorTypeNetwork},
		{"unknown", errors.New("random ldap error"), ErrorTypeUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyLDAPErrorType(tt.err); got != tt.want {
				t.Errorf("classifyLDAPErrorType() = %v, want %v", got, tt.want)
			}
		})
	}
}
