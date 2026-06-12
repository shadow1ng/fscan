//go:build plugin_neo4j || !plugin_selective

package services

import (
	"context"
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
