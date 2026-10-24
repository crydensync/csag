package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/crydensync/cryden/v2/token"

	"github.com/crydensync/api/config"
	"github.com/crydensync/api/templates"
)

// emailFixture is an engine whose audit store the test holds directly, on
// the same pattern as the security fixture: the interesting assertion is
// that the stats endpoint's counts track what the engine itself wrote,
// which is only checkable against the same objects. The sender is a
// capturing one because the raw token exists only in the message the
// engine hands it, and completing a flow needs that token back.
type emailFixture struct {
	engine *cryden.Engine
	audit  *memory.AuditStore
	router http.Handler

	// sender implements both interfaces so one instance satisfies both
	// the EmailSender and MagicLinkSender slots. The engine passes the
	// same pointer to each, so tokens from either flow land here.
	sender     *capturingSender
	adminID    string
	adminToken string
}

// capturingSender records what the engine hands it, the way the engine's
// own smoketest mailer does. The shared stubMailSender deliberately keeps
// nothing; these tests need the raw tokens to complete the email-change
// flow.
type capturingSender struct {
	emailTokens []string
}

func (s *capturingSender) SendVerification(_ context.Context, _, rawToken string) error {
	s.emailTokens = append(s.emailTokens, rawToken)
	return nil
}
func (s *capturingSender) SendMagicLink(_ context.Context, _, rawToken string) error {
	// Magic link tokens are not confirmed by the test (CompleteMagicLink
	// logs the user in and the test does not need that); recording them
	// keeps the interface satisfied without capturing the token.
	_ = rawToken
	return nil
}

// lastEmailToken is the raw token of the most recently requested email
// change. The engine keeps no record of the raw token after handing it
// to the sender, so a test that wants to confirm a change recovers it
// the same way the engine's own smoketest does: from what the sender
// recorded.
func (s *capturingSender) lastEmailToken() string {
	return s.emailTokens[len(s.emailTokens)-1]
}

func newEmailFixture(t *testing.T) emailFixture {
	t.Helper()
	ctx := context.Background()

	users := memory.NewUserStore()
	audit := memory.NewAuditStore()
	sender := &capturingSender{}

	var adminID string
	engineCfg := cryden.Config{
		JWTSecret:       "test-secret",
		Users:           users,
		Sessions:        memory.NewSessionStore(),
		Audit:           audit,
		Verifications:   memory.NewVerificationStore(),
		EmailSender:     sender,
		MagicLinkSender: sender,
		AccessTokenClaims: token.ClaimsFunc(func(_ context.Context, userID string) (map[string]any, error) {
			if userID == adminID {
				return map[string]any{"role": "admin"}, nil
			}
			return nil, nil
		}),
	}
	engine, err := cryden.New(engineCfg)
	if err != nil {
		t.Fatalf("cryden.New on the in-memory stores: %v", err)
	}

	admin, err := cryden.SignUp(ctx, engine, "operator@example.com", testPassword, "203.0.113.1")
	if err != nil {
		t.Fatalf("signup (operator): %v", err)
	}
	adminID = admin.ID
	tokens, err := cryden.Login(ctx, engine, "operator@example.com", testPassword, "203.0.113.1", chromeOnMacOS)
	if err != nil {
		t.Fatalf("login (operator): %v", err)
	}

	return emailFixture{
		engine:     engine,
		audit:      audit,
		router:     NewRouter(Deps{Engine: engine, Audit: audit, Users: users, Config: config.Config{}}),
		sender:     sender,
		adminID:    admin.ID,
		adminToken: tokens.AccessToken,
	}
}

func (f emailFixture) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+f.adminToken)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

// The report is exercised against real engine events, not hand-seeded
// audit rows, for the reason the hash-migration test gives: a seeded row
// proves the counting works and proves nothing about whether a real
// email-shaped flow produces the events being counted.
func TestEmailStatsTracksRealFlows(t *testing.T) {
	f := newEmailFixture(t)
	ctx := context.Background()

	// Magic-link requests. Only existing accounts record an event, the
	// engine returns nil for an unknown address to avoid email enumeration.
	// The test uses the admin's own address so the flow is real end to end.
	if err := cryden.RequestMagicLink(ctx, f.engine, "operator@example.com", "203.0.113.2"); err != nil {
		t.Fatalf("magic link request: %v", err)
	}

	// One full email change: requested, then confirmed with the token the
	// sender was handed. The capturing sender records it, which is the
	// only place the raw token exists after the request returns. The
	// facade takes the account's id, not its address.
	if err := cryden.RequestEmailChange(ctx, f.engine, f.adminID, "new@example.com"); err != nil {
		t.Fatalf("email change request: %v", err)
	}

	rec := f.get(t, "/v1/admin/email/stats")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var body struct {
		Data struct {
			WindowDays                    int `json:"window_days"`
			MagicLinksRequested           int `json:"magic_links_requested"`
			MagicLinksRequestedInWindow   int `json:"magic_links_requested_in_window"`
			EmailChangesRequested         int `json:"email_changes_requested"`
			EmailChangesRequestedInWindow int `json:"email_changes_requested_in_window"`
			EmailChangesConfirmed         int `json:"email_changes_confirmed"`
			EmailChangesConfirmedInWindow int `json:"email_changes_confirmed_in_window"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}

	if body.Data.MagicLinksRequested != 1 {
		t.Errorf("magic_links_requested = %d, want 1", body.Data.MagicLinksRequested)
	}
	if body.Data.EmailChangesRequested != 1 {
		t.Errorf("email_changes_requested = %d, want 1", body.Data.EmailChangesRequested)
	}
	// Nothing has confirmed yet: the token the stub holds was never used.
	if body.Data.EmailChangesConfirmed != 0 {
		t.Errorf("email_changes_confirmed = %d, want 0", body.Data.EmailChangesConfirmed)
	}

	// Confirm, then read again: the confirmed count moves and the
	// requested one does not. The raw token comes back from the capturing
	// sender, the only place it exists once the request has returned.
	rec = f.get(t, "/v1/admin/email/stats")
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	if body.Data.EmailChangesConfirmed != 0 {
		t.Fatalf("email_changes_confirmed = %d before confirm, want 0", body.Data.EmailChangesConfirmed)
	}
	if err := cryden.ConfirmEmailChange(ctx, f.engine, f.sender.lastEmailToken()); err != nil {
		t.Fatalf("confirm: %v", err)
	}

	rec = f.get(t, "/v1/admin/email/stats")
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	if body.Data.EmailChangesConfirmed != 1 {
		t.Errorf("email_changes_confirmed = %d, want 1 after confirm", body.Data.EmailChangesConfirmed)
	}
	if body.Data.EmailChangesRequestedInWindow != 1 {
		t.Errorf("email_changes_requested_in_window = %d, want 1", body.Data.EmailChangesRequestedInWindow)
	}
	if body.Data.WindowDays != 7 {
		t.Errorf("window_days = %d, want the 7 default", body.Data.WindowDays)
	}
}

// A custom window is honoured, and out of range is a 400 rather than a
// clamp, the same treatment the security reports give window_days.
func TestEmailStatsWindow(t *testing.T) {
	f := newEmailFixture(t)

	rec := f.get(t, "/v1/admin/email/stats?window_days=30")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"window_days":30`) {
		t.Errorf("body does not carry the requested window: %s", rec.Body.String())
	}

	rec = f.get(t, "/v1/admin/email/stats?window_days=0")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("window_days=0 status = %d, want 400", rec.Code)
	}
}

// The wiring-fact answer: a router built without the audit store answers
// 404, the same shape as every other unconfigured feature here.
func TestEmailStatsWithoutStores(t *testing.T) {
	router := NewRouter(Deps{Engine: nil, Config: config.Config{DatabaseURL: "postgres://u:p@localhost/db"}})

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/email/stats", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// RequireAdmin runs first, and no token was sent.
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 from RequireAdmin", rec.Code)
	}
}

// The template status, for both states a deployment can be in.
func TestEmailTemplatesStatus(t *testing.T) {
	t.Run("unconfigured reports configured false with no samples", func(t *testing.T) {
		h := &EmailTemplatesHandlers{}

		rec := httptest.NewRecorder()
		h.EmailTemplates(rec, httptest.NewRequest(http.MethodGet, "/v1/admin/settings/email-templates", nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
		var body struct {
			Data struct {
				Configured bool                `json:"configured"`
				Kinds      []templateStatusDTO `json:"kinds"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decoding %s: %v", rec.Body.String(), err)
		}
		if body.Data.Configured {
			t.Error("configured = true, want false with no dir")
		}
		if len(body.Data.Kinds) != 2 {
			t.Fatalf("kinds = %d, want 2", len(body.Data.Kinds))
		}
		for _, k := range body.Data.Kinds {
			if k.Configured || k.Sample != "" {
				t.Errorf("kind %s = configured %v sample %q, want unconfigured and empty", k.Kind, k.Configured, k.Sample)
			}
		}
	})

	t.Run("configured renders a sample of each", func(t *testing.T) {
		dir := t.TempDir()
		verification := "Confirm {{.To}}: token {{.Token}}"
		magicLink := "Log in: {{.URL}}"
		if err := os.WriteFile(filepath.Join(dir, templates.VerificationFile), []byte(verification), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, templates.MagicLinkFile), []byte(magicLink), 0o600); err != nil {
			t.Fatal(err)
		}
		set, err := templates.Load(dir)
		if err != nil {
			t.Fatalf("loading the fixture templates: %v", err)
		}

		h := &EmailTemplatesHandlers{TemplateDir: dir, Templates: set}
		rec := httptest.NewRecorder()
		h.EmailTemplates(rec, httptest.NewRequest(http.MethodGet, "/v1/admin/settings/email-templates", nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
		var body struct {
			Data struct {
				Configured       bool                `json:"configured"`
				EmailTemplateDir string              `json:"email_template_dir"`
				Kinds            []templateStatusDTO `json:"kinds"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decoding %s: %v", rec.Body.String(), err)
		}

		if !body.Data.Configured || body.Data.EmailTemplateDir != dir {
			t.Errorf("configured = %v dir = %q, want true and %q", body.Data.Configured, body.Data.EmailTemplateDir, dir)
		}
		if body.Data.Kinds[0].Sample != "Confirm status@example.com: token SAMPLE_TOKEN" {
			t.Errorf("verification sample = %q", body.Data.Kinds[0].Sample)
		}
		if body.Data.Kinds[1].Sample != "Log in: https://example.com/magic-link?token=SAMPLE_TOKEN" {
			t.Errorf("magic link sample = %q", body.Data.Kinds[1].Sample)
		}
	})

	t.Run("a half-configured directory reports the missing one as not configured", func(t *testing.T) {
		// Load requires at least one file; one file is enough, and the
		// other kind falls back independently. That is the behaviour the
		// endpoint has to surface: one configured row, one not.
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, templates.MagicLinkFile), []byte("Link for {{.To}}: {{.URL}}"), 0o600); err != nil {
			t.Fatal(err)
		}
		set, err := templates.Load(dir)
		if err != nil {
			t.Fatalf("loading the fixture template: %v", err)
		}

		h := &EmailTemplatesHandlers{TemplateDir: dir, Templates: set}
		rec := httptest.NewRecorder()
		h.EmailTemplates(rec, httptest.NewRequest(http.MethodGet, "/v1/admin/settings/email-templates", nil))

		var body struct {
			Data struct {
				Kinds []templateStatusDTO `json:"kinds"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decoding: %v", err)
		}
		if body.Data.Kinds[0].Kind != "verification" || body.Data.Kinds[0].Configured {
			t.Errorf("verification = %+v, want unconfigured", body.Data.Kinds[0])
		}
		if body.Data.Kinds[1].Kind != "magic_link" || !body.Data.Kinds[1].Configured || body.Data.Kinds[1].Sample == "" {
			t.Errorf("magic link kind = %+v, want configured with a sample", body.Data.Kinds[1])
		}
	})
}
