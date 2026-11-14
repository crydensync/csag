package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// consumerEmailSender relays generated tokens to a consuming application. The
// consumer owns the provider key and performs actual email delivery.
type consumerEmailSender struct {
	URL   string
	Token string
	HTTP  *http.Client
}

type consumerEmailRequest struct {
	Kind  string `json:"kind"`
	To    string `json:"to"`
	Token string `json:"token"`
}

func newConsumerEmailSender(endpoint, token string) *consumerEmailSender {
	return &consumerEmailSender{URL: endpoint, Token: token, HTTP: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (s *consumerEmailSender) SendVerification(ctx context.Context, to, rawToken string) error {
	return s.send(ctx, "verification", to, rawToken)
}

func (s *consumerEmailSender) SendMagicLink(ctx context.Context, to, rawToken string) error {
	return s.send(ctx, "magic_link", to, rawToken)
}

func (s *consumerEmailSender) send(ctx context.Context, kind, to, rawToken string) error {
	body, err := json.Marshal(consumerEmailRequest{Kind: kind, To: to, Token: rawToken})
	if err != nil {
		return fmt.Errorf("encode consumer email request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create consumer email request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("consumer email delivery request failed")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("consumer email delivery returned HTTP %d", resp.StatusCode)
	}
	return nil
}
