package operator

import (
	"errors"
	"testing"
)

func TestNormalizeInviteEmail(t *testing.T) {
	got, err := normalizeInviteEmail("  Admin@Example.COM ")
	if err != nil || got != "admin@example.com" {
		t.Fatalf("normalizeInviteEmail() = %q, %v", got, err)
	}
	for _, input := range []string{"", "name <admin@example.com>", "bad", "a@b@c"} {
		if _, err := normalizeInviteEmail(input); !errors.Is(err, ErrInvalidInvitationEmail) {
			t.Errorf("normalizeInviteEmail(%q) error = %v", input, err)
		}
	}
}

func TestInvitationRoleValidation(t *testing.T) {
	for _, role := range []string{"admin", "viewer"} {
		if role != "admin" && role != "viewer" {
			t.Errorf("unexpected allowed invitation role %q", role)
		}
	}
	for _, role := range []string{"owner", "", "user"} {
		if role == "admin" || role == "viewer" {
			t.Errorf("unexpected allowed invitation role %q", role)
		}
	}
}
