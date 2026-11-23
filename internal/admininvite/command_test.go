package admininvite

import (
	"strings"
	"testing"
)

func TestBuildInviteURL(t *testing.T) {
	got, err := buildInviteURL("https://console.example/base/", "abc_DEF-123")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://console.example/base/invite?token=abc_DEF-123" {
		t.Fatalf("URL = %q", got)
	}
}

func TestValidateConsoleURL(t *testing.T) {
	for _, value := range []string{"https://console.example", "http://localhost:3000"} {
		if err := validateConsoleURL(value); err != nil {
			t.Errorf("validateConsoleURL(%q): %v", value, err)
		}
	}
	for _, value := range []string{"", "//console.example", "ftp://console.example", "https://user:pass@console.example", "https://console.example?x=1", "https://console.example/#frag"} {
		if err := validateConsoleURL(value); err == nil {
			t.Errorf("validateConsoleURL(%q) succeeded", value)
		}
	}
}

func TestRunRequiresAllFlagsBeforeConnecting(t *testing.T) {
	var stderr strings.Builder
	err := Run(nil, &strings.Builder{}, &stderr)
	if err == nil || !strings.Contains(err.Error(), "--console-url") {
		t.Fatalf("Run() error = %v, want required flag usage", err)
	}
}
