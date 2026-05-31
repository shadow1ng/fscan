package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRabbitMQManagementRejectsGenericHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("plain http service"))
	}))
	defer server.Close()

	result := NewRabbitMQPlugin().testManagementInterface(context.Background(), hostInfoFromServer(t, server), testSession())
	if result.Success {
		t.Fatalf("testManagementInterface reported generic HTTP as RabbitMQ: %#v", result)
	}
}
