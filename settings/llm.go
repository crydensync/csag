package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const (
	LLMProviderKindAnthropic        = "anthropic"
	LLMProviderKindOpenAICompatible = "openai-compatible"
)

// DefaultLLMModel is a safe starter model identifier for Anthropic.
const DefaultLLMModel = "claude-opus-5"

// The bounds on MaxTokens. The floor is not zero: a provider asked for
// zero output tokens would answer with an empty response that this repo
// would then fail to parse, which reads as a broken provider rather than
// as a bad setting. The ceiling keeps one AI query from consuming a
// month's budget in a single call.
const (
	MinLLMMaxTokens = 256
	MaxLLMMaxTokens = 8192
	// DefaultLLMMaxTokens is room for a QueryIntent plus the model's
	// reasoning about it. The output here is a small JSON object, not
	// prose, so this is generous rather than tight.
	DefaultLLMMaxTokens = 2048
	DefaultLLMRPM       = 60
	MaxLLMRPM           = 10000
)

const DefaultLLMTemperature = 0.2

// ErrInvalidLLMProvider means the supplied configuration cannot back a
// working provider. Returned instead of storing it, because a saved
// setting that fails at the first real use is worse than a refused save:
// the operator finds out from a user, not from the form.
var ErrInvalidLLMProvider = errors.New("settings: invalid LLM provider configuration")

// LLMProviderConfig is what a console reads and writes. It is the
// plaintext shape — it is marshalled to JSON, sealed, and only then
// handed to Secrets, so it exists in memory and inside the ciphertext and
// nowhere else.
type LLMProviderConfig struct {
	Kind        string  `json:"kind"`
	Model       string  `json:"model"`
	APIKey      string  `json:"api_key"`
	BaseURL     string  `json:"base_url,omitempty"`
	MaxTokens   int     `json:"max_tokens"`
	Temperature float64 `json:"temperature"`
	RPM         int     `json:"rpm"`
}

// Validate checks a configuration that is about to be stored. The stored
// value is the one every later read has to work with, so this is the only
// place the rule can be enforced — a handler that trusted a form would be
// enforcing it in the wrong layer.
func (c LLMProviderConfig) Validate() error {
	if c.Kind != LLMProviderKindAnthropic && c.Kind != LLMProviderKindOpenAICompatible {
		return fmt.Errorf("%w: kind must be anthropic or openai-compatible", ErrInvalidLLMProvider)
	}
	if strings.TrimSpace(c.Model) == "" || strings.TrimSpace(c.APIKey) == "" {
		return fmt.Errorf("%w: model and api_key are required", ErrInvalidLLMProvider)
	}
	if c.Kind == LLMProviderKindOpenAICompatible || strings.TrimSpace(c.BaseURL) != "" {
		if err := validateProviderBaseURL(c.BaseURL); err != nil {
			return err
		}
	}
	if c.MaxTokens < MinLLMMaxTokens || c.MaxTokens > MaxLLMMaxTokens {
		return fmt.Errorf("%w: max_tokens must be between %d and %d", ErrInvalidLLMProvider, MinLLMMaxTokens, MaxLLMMaxTokens)
	}
	if c.Temperature < 0 || c.Temperature > 2 {
		return fmt.Errorf("%w: temperature must be between 0 and 2", ErrInvalidLLMProvider)
	}
	if c.RPM < 1 || c.RPM > MaxLLMRPM {
		return fmt.Errorf("%w: rpm must be between 1 and %d", ErrInvalidLLMProvider, MaxLLMRPM)
	}
	return nil
}

func validateProviderBaseURL(value string) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%w: base_url must be an http(s) URL without credentials, query or fragment", ErrInvalidLLMProvider)
	}
	return nil
}

// Redacted returns the copy of this configuration that is safe to send to
// a console: everything except the credential, with a flag saying whether
// one is set.
//
// This is a method on the config rather than something each handler
// remembers to do, and that is the point. A response that carried the API
// key would put it in a browser's memory, in a devtools panel, in a
// screenshot of the settings screen — and the whole reason the key is
// encrypted at rest is that it is worth stealing.
func (c LLMProviderConfig) Redacted() RedactedLLMProvider {
	return RedactedLLMProvider{
		Kind:        c.Kind,
		Model:       c.Model,
		BaseURL:     c.BaseURL,
		MaxTokens:   c.MaxTokens,
		Temperature: c.Temperature,
		RPM:         c.RPM,
		APIKeySet:   c.APIKey != "",
		Configured:  true,
	}
}

// RedactedLLMProvider is what GET returns. Separate from
// LLMProviderConfig rather than the same struct with an empty APIKey
// field, so a handler cannot accidentally serialise the credential by
// using the wrong type — the credential is not a field here at all.
type RedactedLLMProvider struct {
	Kind        string  `json:"kind"`
	Model       string  `json:"model"`
	BaseURL     string  `json:"base_url"`
	MaxTokens   int     `json:"max_tokens"`
	Temperature float64 `json:"temperature"`
	RPM         int     `json:"rpm"`
	// APIKeySet says whether a credential is stored. Enough for a console
	// to render "••••••••  saved" versus "not set", and not enough to
	// reconstruct anything.
	APIKeySet bool `json:"api_key_set"`
	// Configured distinguishes a stored provider from the zero value this
	// struct has when nothing is stored. Both have empty strings, and a
	// console that cannot tell them apart shows a blank form where it
	// should show "not configured yet".
	Configured bool `json:"configured"`
}

// MarshalLLMProvider seals and encodes a configuration for storage.
//
// The seal-and-encode pair lives here rather than in the handler so that
// "JSON, then encrypted" has exactly one spelling: a second caller that
// encoded differently would produce rows the reader below cannot open.
func MarshalLLMProvider(c LLMProviderConfig) ([]byte, error) {
	return json.Marshal(c)
}

// UnmarshalLLMProvider decodes what MarshalLLMProvider produced. It
// receives plaintext, so it must only ever be handed the output of
// Secrets.Get.
func UnmarshalLLMProvider(plaintext []byte) (LLMProviderConfig, error) {
	var c LLMProviderConfig
	if err := json.Unmarshal(plaintext, &c); err != nil {
		return LLMProviderConfig{}, fmt.Errorf("settings: decoding the stored LLM provider: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(plaintext, &fields); err != nil {
		return LLMProviderConfig{}, fmt.Errorf("settings: decoding the stored LLM provider fields: %w", err)
	}
	if _, exists := fields["temperature"]; !exists {
		c.Temperature = DefaultLLMTemperature
	}
	if c.RPM == 0 {
		c.RPM = DefaultLLMRPM
	}
	if c.MaxTokens == 0 {
		c.MaxTokens = DefaultLLMMaxTokens
	}
	return c, nil
}
