//go:build plugin_ldap || !plugin_selective

package services

import (
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
