//go:build !plugin_selective || plugin_activemq || plugin_imap || plugin_pop3 || plugin_redis

package services

import (
	"fmt"
	"strconv"
	"strings"
)

func hasLineBreak(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}

func rejectLineBreaks(values ...string) error {
	for _, value := range values {
		if hasLineBreak(value) {
			return fmt.Errorf("credential contains line break")
		}
	}
	return nil
}

func imapQuotedString(s string) (string, error) {
	if hasLineBreak(s) {
		return "", fmt.Errorf("imap credential contains line break")
	}
	return strconv.Quote(s), nil
}

func buildIMAPLoginCommand(tag, username, password string) (string, error) {
	quotedUser, err := imapQuotedString(username)
	if err != nil {
		return "", err
	}
	quotedPass, err := imapQuotedString(password)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s LOGIN %s %s\r\n", tag, quotedUser, quotedPass), nil
}

func buildRedisAuthCommand(password string) []byte {
	return buildRedisCommand("AUTH", password)
}

func buildRedisCommand(args ...string) []byte {
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, arg := range args {
		_, _ = fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(arg), arg)
	}
	return []byte(b.String())
}
