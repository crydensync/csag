package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConsumerEmailSenderRelaysMessageToConsumer(t *testing.T) {
	for _, tc := range []struct {
		name string
		send func(*consumerEmailSender, context.Context, string, string) error
		kind string
	}{
		{name: "magic link", kind: "magic_link", send: func(s *consumerEmailSender, ctx context.Context, to, token string) error {
			return s.SendMagicLink(ctx, to, token)
		}},
		{name: "verification", kind: "verification", send: func(s *consumerEmailSender, ctx context.Context, to, token string) error {
			return s.SendVerification(ctx, to, token)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const sharedSecret = "local-test-secret"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("method = %q, want POST", r.Method)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer "+sharedSecret {
					t.Errorf("authorization was not the configured bearer secret")
				}
				var got consumerEmailRequest
				if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
					t.Errorf("decode relay body: %v", err)
					return
				}
				if got.Kind != tc.kind || got.To != "person@example.test" || got.Token != "opaque-token" {
					t.Errorf("relay body = %+v", got)
				}
				w.WriteHeader(http.StatusAccepted)
			}))
			defer server.Close()

			sender := newConsumerEmailSender(server.URL, sharedSecret)
			if err := tc.send(sender, context.Background(), "person@example.test", "opaque-token"); err != nil {
				t.Fatalf("send: %v", err)
			}
		})
	}
}

func TestConsumerEmailSenderDoesNotFollowRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.invalid/collect", http.StatusFound)
	}))
	defer server.Close()

	err := newConsumerEmailSender(server.URL, "local-test-secret").SendMagicLink(context.Background(), "person@example.test", "opaque-token")
	if err == nil {
		t.Fatal("send succeeded after the consumer redirected it")
	}
}
