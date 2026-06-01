//go:build plugin_oracle || !plugin_selective

package services

import (
	"bytes"
	"testing"
)

func TestOracleConnectDataDoesNotExposeClientIdentity(t *testing.T) {
	connectData := oracleConnectData("db.example", 1521, "ORCL")

	for _, value := range []string{"CID=", "PROGRAM=", "USER=", "fscan"} {
		if bytes.Contains([]byte(connectData), []byte(value)) {
			t.Fatalf("oracle connect data contains client-identifying value %q: %s", value, connectData)
		}
	}
}
