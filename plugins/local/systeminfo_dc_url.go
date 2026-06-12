package local

import (
	"fmt"
	"net"
	"strconv"
)

func ldapURL(host string, port int) string {
	return fmt.Sprintf("ldap://%s", net.JoinHostPort(host, strconv.Itoa(port)))
}
