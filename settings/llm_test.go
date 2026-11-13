package settings

import "testing"

func TestOpenAICompatibleProviderValidationAndRedaction(t *testing.T) {
	config := LLMProviderConfig{Kind: LLMProviderKindOpenAICompatible, Model: "model-x", APIKey: "secret", BaseURL: "https://provider.example/v1", MaxTokens: 2048, Temperature: 0.2, RPM: 60}
	if err := config.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	redacted := config.Redacted()
	if !redacted.Configured || !redacted.APIKeySet || redacted.BaseURL != config.BaseURL || redacted.RPM != 60 {
		t.Fatalf("redacted config = %+v", redacted)
	}
	for _, baseURL := range []string{"http://user:password@host/v1", "https://host/v1?token=x", "file:///tmp/x", "not-a-url"} {
		config.BaseURL = baseURL
		if err := config.Validate(); err == nil {
			t.Errorf("Validate accepted unsafe URL %q", baseURL)
		}
	}
}

func TestUnmarshalLLMProviderDefaultsNewFieldsAndPreservesZeroTemperature(t *testing.T) {
	legacy, err := UnmarshalLLMProvider([]byte(`{"kind":"anthropic","model":"legacy","api_key":"key","max_tokens":1024}`))
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Temperature != DefaultLLMTemperature || legacy.RPM != DefaultLLMRPM {
		t.Fatalf("legacy defaults = temperature %v rpm %d", legacy.Temperature, legacy.RPM)
	}
	zero, err := UnmarshalLLMProvider([]byte(`{"kind":"anthropic","model":"legacy","api_key":"key","max_tokens":1024,"temperature":0}`))
	if err != nil {
		t.Fatal(err)
	}
	if zero.Temperature != 0 {
		t.Fatalf("explicit zero temperature changed to %v", zero.Temperature)
	}
}
