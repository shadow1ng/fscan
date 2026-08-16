//go:build plugin_smtp || !plugin_selective

package services

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestClassifySMTPErrorType(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorType
	}{
		{"nil error", nil, ErrorTypeUnknown},
		{"535 authentication failed", errors.New("535 authentication failed"), ErrorTypeAuth},
		{"relay access denied", errors.New("relay access denied"), ErrorTypeAuth},
		{"connection refused", errors.New("connection refused"), ErrorTypeNetwork},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifySMTPErrorType(tt.err)
			if got != tt.want {
				t.Errorf("classifySMTPErrorType(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestSMTPClientIdentity(t *testing.T) {
	tests := []struct {
		name string
		addr net.Addr
		want string
	}{
		{name: "IPv4", addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 49152}, want: "[192.0.2.10]"},
		{name: "IPv6", addr: &net.TCPAddr{IP: net.ParseIP("2001:db8::10"), Port: 49152}, want: "[IPv6:2001:db8::10]"},
		{name: "unknown address", addr: nil, want: "localhost.localdomain"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := smtpClientIdentity(tt.addr); got != tt.want {
				t.Fatalf("smtpClientIdentity() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSMTPHandshakeConsumesGreetingAndUsesEHLO(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(server)
		if _, err := fmt.Fprint(server, "220-mail.example ESMTP ready\r\n220 service ready\r\n"); err != nil {
			done <- err
			return
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			done <- err
			return
		}
		if line != "EHLO localhost.localdomain\r\n" {
			done <- fmt.Errorf("first command = %q", line)
			return
		}
		_, err = fmt.Fprint(server, "250-mail.example\r\n250 VRFY\r\n")
		done <- err
	}()

	if _, err := smtpHandshake(client); err != nil {
		t.Fatalf("smtpHandshake() error = %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSMTPHandshakeFallsBackToHELO(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(server)
		if _, err := fmt.Fprint(server, "220 mail.example SMTP ready\r\n"); err != nil {
			done <- err
			return
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			done <- err
			return
		}
		if !strings.HasPrefix(line, "EHLO ") {
			done <- fmt.Errorf("first command = %q", line)
			return
		}
		if _, err := fmt.Fprint(server, "500 EHLO not supported\r\n"); err != nil {
			done <- err
			return
		}
		line, err = reader.ReadString('\n')
		if err != nil {
			done <- err
			return
		}
		if !strings.HasPrefix(line, "HELO ") {
			done <- fmt.Errorf("fallback command = %q", line)
			return
		}
		_, err = fmt.Fprint(server, "250 mail.example\r\n")
		done <- err
	}()

	if _, err := smtpHandshake(client); err != nil {
		t.Fatalf("smtpHandshake() error = %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
