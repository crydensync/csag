package aiprovider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestChatCompletionsUsesConfiguredBaseURLKeyAndModel(t *testing.T) {
	var chatCalled, modelsCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/v1/chat/completions":
			chatCalled = true
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["model"] != "model-x" || body["max_tokens"] != float64(1536) {
				t.Errorf("request body = %#v", body)
			}
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"entity\":\"users\",\"filters\":[],\"aggregate\":\"count\",\"group_by\":\"\",\"limit\":1}"}}]}`))
		case "/v1/models":
			modelsCalled = true
			_, _ = w.Write([]byte(`{"data":[{"id":"model-x"},{"id":"model-y"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	provider, err := NewChatCompletions(ChatConfig{APIKey: "secret", BaseURL: server.URL + "/v1", Model: "model-x", MaxTokens: 1536, Temperature: 0.4})
	if err != nil {
		t.Fatal(err)
	}
	if want := 60 * time.Second; provider.client.Timeout != want {
		t.Fatalf("provider timeout = %s, want %s", provider.client.Timeout, want)
	}
	intent, err := provider.ParseQueryIntent(context.Background(), "count users")
	if err != nil {
		t.Fatal(err)
	}
	if intent.Entity != "users" || !chatCalled {
		t.Fatalf("intent=%+v called=%v", intent, chatCalled)
	}
	models, err := provider.ListModels(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !modelsCalled || len(models) != 2 || models[0] != "model-x" {
		t.Fatalf("models=%v called=%v", models, modelsCalled)
	}
}
