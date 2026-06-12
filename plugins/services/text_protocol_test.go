//go:build !plugin_selective || plugin_activemq || plugin_imap || plugin_pop3 || plugin_redis

package services

import "testing"

func TestBuildRedisAuthCommandUsesBulkString(t *testing.T) {
	got := string(buildRedisAuthCommand("pa ss\r\nword"))
	want := "*2\r\n$4\r\nAUTH\r\n$11\r\npa ss\r\nword\r\n"
	if got != want {
		t.Fatalf("buildRedisAuthCommand() = %q, want %q", got, want)
	}
}

func TestBuildRedisCommandKeepsInjectedNewlinesInsideBulkString(t *testing.T) {
	got := string(buildRedisCommand("CONFIG", "SET", "dir", "/tmp\r\nSAVE"))
	want := "*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$10\r\n/tmp\r\nSAVE\r\n"
	if got != want {
		t.Fatalf("buildRedisCommand() = %q, want %q", got, want)
	}
}

func TestBuildIMAPLoginCommandQuotesCredentials(t *testing.T) {
	got, err := buildIMAPLoginCommand("a001", `user name`, `pa"ss\word`)
	if err != nil {
		t.Fatalf("buildIMAPLoginCommand() error = %v", err)
	}
	want := "a001 LOGIN \"user name\" \"pa\\\"ss\\\\word\"\r\n"
	if got != want {
		t.Fatalf("buildIMAPLoginCommand() = %q, want %q", got, want)
	}
}

func TestTextProtocolCredentialsRejectLineBreaks(t *testing.T) {
	if _, err := buildIMAPLoginCommand("a001", "user", "pa\nss"); err == nil {
		t.Fatal("buildIMAPLoginCommand() error = nil, want line break rejection")
	}
	if err := rejectLineBreaks("user", "pa\rss"); err == nil {
		t.Fatal("rejectLineBreaks() error = nil, want line break rejection")
	}
	if err := rejectLineBreaks("user", "pass"); err != nil {
		t.Fatalf("rejectLineBreaks() error = %v, want nil", err)
	}
}
