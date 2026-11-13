package aiprovider

import (
	"fmt"

	crydenai "github.com/crydensync/cryden/v2/ai"

	"github.com/crydensync/api/settings"
)

// NewLLM constructs the configured provider adapter. OpenAI-compatible
// endpoints make the provider URL and API key deployment-configurable without
// hardcoding a vendor list into this API.
func NewLLM(config settings.LLMProviderConfig) (crydenai.LLMProvider, error) {
	var provider crydenai.LLMProvider
	var err error
	switch config.Kind {
	case settings.LLMProviderKindAnthropic:
		provider, err = NewAnthropic(AnthropicConfig{
			APIKey: config.APIKey, BaseURL: config.BaseURL, Model: config.Model,
			MaxTokens: config.MaxTokens, Temperature: config.Temperature,
		})
	case settings.LLMProviderKindOpenAICompatible:
		provider, err = NewChatCompletions(ChatConfig{
			APIKey: config.APIKey, BaseURL: config.BaseURL, Model: config.Model,
			MaxTokens: config.MaxTokens, Temperature: config.Temperature,
		})
	default:
		return nil, fmt.Errorf("aiprovider: unsupported provider kind %q", config.Kind)
	}
	if err != nil {
		return nil, err
	}
	return meterProvider(provider, config.Kind, config.Model, config.RPM), nil
}
