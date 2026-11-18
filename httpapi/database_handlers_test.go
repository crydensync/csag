package httpapi

import (
	"strings"
	"testing"
)

func TestDatabasePreviewUsesReviewedColumnsOnly(t *testing.T) {
	cases := map[string][]string{
		"users":                      {"id", "email", "created_at"},
		"sessions":                   {"id", "user_id", "revoked_at"},
		"totp_secrets":               {"user_id", "confirmed_at"},
		"webauthn_credentials":       {"id", "nickname"},
		"recovery_codes":             {"user_id", "used_at"},
		"api_keys":                   {"id", "prefix", "revoked_at"},
		"settings":                   {"key", "updated_at"},
		"webhook_deliveries":         {"id", "status", "attempts"},
		"operator_stepup_challenges": {"user_id", "purpose"},
	}
	for table, want := range cases {
		got := makeColumnSet(safeDatabaseColumns[table])
		for _, column := range want {
			if _, ok := got[column]; !ok {
				t.Errorf("%s omits reviewed column %q", table, column)
			}
		}
	}
	for table, forbidden := range map[string][]string{
		"users": {"password_hash"}, "sessions": {"token_hash"},
		"totp_secrets":         {"encrypted_secret"},
		"webauthn_credentials": {"credential_id", "credential_data"},
		"recovery_codes":       {"code_hash"}, "api_keys": {"key_hash"},
		"user_metadata": {"value"}, "settings": {"value"},
		"webhook_deliveries":         {"payload", "error"},
		"digest_runs":                {"digest_text"},
		"operator_stepup_challenges": {"session_data", "token_hash"},
	} {
		got := makeColumnSet(safeDatabaseColumns[table])
		for _, column := range forbidden {
			if _, ok := got[column]; ok {
				t.Errorf("%s exposes protected column %q", table, column)
			}
		}
	}
}

func TestQuoteIdentifierEscapesQuotes(t *testing.T) {
	if got, want := quoteIdentifier(`a"b`), `"a""b"`; !strings.EqualFold(got, want) {
		t.Fatalf("quoteIdentifier = %q, want %q", got, want)
	}
}
