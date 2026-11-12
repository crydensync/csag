package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// WebhookEndpointConfig is the runtime destination for queued events. Its
// secret is only returned to the worker and is never part of an API response.
type WebhookEndpointConfig struct {
	URL    string `json:"url"`
	Secret string `json:"secret"`
}

func (c WebhookEndpointConfig) Validate() error {
	u, err := url.ParseRequestURI(strings.TrimSpace(c.URL))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("url must be a valid http or https URL")
	}
	if u.Scheme != "https" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
		return errors.New("webhook URLs must use https")
	}
	if strings.TrimSpace(c.Secret) == "" {
		return errors.New("secret is required")
	}
	return nil
}

func UnmarshalWebhookEndpoint(raw []byte) (WebhookEndpointConfig, error) {
	var c WebhookEndpointConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, fmt.Errorf("settings: decoding webhook endpoint: %w", err)
	}
	if err := c.Validate(); err != nil {
		return c, fmt.Errorf("settings: invalid webhook endpoint: %w", err)
	}
	return c, nil
}
