//go:build plugin_neo4j || !plugin_selective

package services

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNeo4jIdentifyRejectsGenericHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("plain http service"))
	}))
	defer server.Close()

	result := NewNeo4jPlugin().identifyService(context.Background(), hostInfoFromServer(t, server), testSession())
	if result.Success {
		t.Fatalf("identifyService reported generic HTTP as Neo4j: %#v", result)
	}
}

func TestNeo4jUnauthorizedRequiresNeo4jBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	result := NewNeo4jPlugin().testUnauthorizedAccess(context.Background(), hostInfoFromServer(t, server), testSession())
	if result != nil && result.Success {
		t.Fatalf("testUnauthorizedAccess reported generic 200 as Neo4j: %#v", result)
	}
}

func TestClassifyNeo4jErrorType(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorType
	}{
		{"nil", nil, ErrorTypeUnknown},
		{"authentication failed", errors.New("authentication failed"), ErrorTypeAuth},
		{"401 unauthorized", errors.New("401 unauthorized"), ErrorTypeAuth},
		{"connection refused", errors.New("connection refused"), ErrorTypeNetwork},
		{"unknown", errors.New("random neo4j error"), ErrorTypeUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyNeo4jErrorType(tt.err); got != tt.want {
				t.Errorf("classifyNeo4jErrorType() = %v, want %v", got, tt.want)
			}
		})
	}
}
