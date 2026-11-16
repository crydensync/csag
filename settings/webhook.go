package settings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// WebhookEndpointConfig is the runtime destination for queued events. Its
// secret is only returned to the worker and is never part of an API response.
type WebhookEndpointConfig struct {
	Name   string `json:"name,omitempty"`
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

// WebhookEndpointKey returns the encrypted setting key for one stable ID.
func WebhookEndpointKey(id string) string {
	if id == "default" {
		return KeyWebhookEndpoint
	}
	return KeyWebhookEndpointPrefix + id
}

// RuntimeWebhookEndpoints reads all valid runtime destinations. Environment
// settings are deliberately not included; the caller applies those only when
// the runtime set is empty, preserving the established override behavior.
func RuntimeWebhookEndpoints(ctx context.Context, secrets *Secrets) (map[string]WebhookEndpointConfig, error) {
	keys, err := secrets.Keys(ctx)
	if err != nil {
		return nil, err
	}
	items := make(map[string]WebhookEndpointConfig)
	for _, key := range keys {
		id := ""
		if key == KeyWebhookEndpoint {
			id = "default"
		} else if strings.HasPrefix(key, KeyWebhookEndpointPrefix) {
			id = strings.TrimPrefix(key, KeyWebhookEndpointPrefix)
		}
		if id == "" {
			continue
		}
		raw, err := secrets.Get(ctx, key)
		if err != nil {
			return nil, err
		}
		config, err := UnmarshalWebhookEndpoint(raw)
		if err != nil {
			return nil, err
		}
		if config.Name == "" {
			config.Name = "Default"
		}
		items[id] = config
	}
	return items, nil
}
