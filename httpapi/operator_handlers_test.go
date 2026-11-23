package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/crydensync/api/operator"
)

type operatorListStub []operator.Operator

func (s operatorListStub) List(context.Context) ([]operator.Operator, error) { return s, nil }

func TestOperatorListReturnsLiveRoster(t *testing.T) {
	created := time.Date(2026, time.November, 14, 12, 0, 0, 0, time.UTC)
	h := OperatorHandlers{Store: operatorListStub{{
		UserID: "01a1d782-0635-7e41-bd60-50e1cfef5fc8", Email: "owner@example.com", Role: "owner", CreatedAt: created,
	}}}
	rec := httptest.NewRecorder()
	h.List(rec, httptest.NewRequest("GET", "/v1/admin/operators", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Data struct {
			Operators []operator.Operator `json:"operators"`
			Total     int                 `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.Total != 1 || len(response.Data.Operators) != 1 {
		t.Fatalf("unexpected roster: %+v", response.Data)
	}
	if got := response.Data.Operators[0]; got.Role != "owner" || got.Email != "owner@example.com" || !got.CreatedAt.Equal(created) {
		t.Fatalf("unexpected operator: %+v", got)
	}
	var raw struct {
		Data struct {
			Operators []map[string]json.RawMessage `json:"operators"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw.Data.Operators) != 1 {
		t.Fatalf("unexpected raw operator roster: %+v", raw.Data.Operators)
	}
	for _, key := range []string{"user_id", "email", "role", "created_at"} {
		if _, ok := raw.Data.Operators[0][key]; !ok {
			t.Errorf("operator JSON is missing %q: %+v", key, raw.Data.Operators[0])
		}
	}
	if len(raw.Data.Operators[0]) != 4 {
		t.Errorf("operator JSON has unexpected fields: %+v", raw.Data.Operators[0])
	}
}

func TestOperatorScopedActionsRejectNonOperators(t *testing.T) {
	h := OperatorHandlers{Store: operatorListStub{{
		UserID: "01a1d782-0635-7e41-bd60-50e1cfef5fc8", Email: "owner@example.com", Role: "owner",
	}}}
	rec := httptest.NewRecorder()
	if h.requireOperator(rec, httptest.NewRequest(http.MethodGet, "/", nil), "01a1d782-0635-7e41-bd60-50e1cfef5fd9") {
		t.Fatal("non-operator target was accepted")
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec).Code; got != "operator_not_found" {
		t.Fatalf("error code = %q, want operator_not_found", got)
	}
}

func TestValidStepUpPurposes(t *testing.T) {
	for _, purpose := range []string{"operator_role_change", "operator_remove", "operator_session_revoke", "operator_passkey_remove", "operator_invite", "secret_reveal", "secret_mutation"} {
		if !validStepUpPurpose(purpose) {
			t.Errorf("%q should be accepted", purpose)
		}
	}
	for _, purpose := range []string{"", "session_revoke"} {
		if validStepUpPurpose(purpose) {
			t.Errorf("%q should be rejected", purpose)
		}
	}
}

func TestStepUpPurposeSeparatesOwnerActionsFromAdminSecrets(t *testing.T) {
	adminID := "01a1d782-0635-7e41-bd60-50e1cfef5fc8"
	h := OperatorHandlers{Store: operatorListStub{{UserID: adminID, Email: "admin@example.com", Role: "admin"}}}
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r = r.WithContext(context.WithValue(r.Context(), userIDContextKey, adminID))

	operatorAction := httptest.NewRecorder()
	if h.authorizeStepUpPurpose(operatorAction, r, "operator_remove") {
		t.Fatal("admin was allowed to step up for an owner-only operator action")
	}
	if operatorAction.Code != http.StatusForbidden {
		t.Fatalf("operator action status = %d, want 403", operatorAction.Code)
	}
	inviteAction := httptest.NewRecorder()
	if h.authorizeStepUpPurpose(inviteAction, r, "operator_invite") {
		t.Fatal("admin was allowed to step up to create an operator invitation")
	}
	if inviteAction.Code != http.StatusForbidden {
		t.Fatalf("invite action status = %d, want 403", inviteAction.Code)
	}

	secretAction := httptest.NewRecorder()
	if !h.authorizeStepUpPurpose(secretAction, r, "secret_mutation") {
		t.Fatalf("admin was refused a secret step-up: %s", secretAction.Body.String())
	}
}

func TestStepUpFailureWindowLocksAfterFiveFailures(t *testing.T) {
	now := time.Date(2026, time.November, 14, 12, 0, 0, 0, time.UTC)
	started := now.Add(-time.Minute)
	count, windowStart, lockedUntil := nextStepUpFailure(4, started, now)
	if count != stepUpFailureLimit {
		t.Fatalf("failure count = %d, want %d", count, stepUpFailureLimit)
	}
	if !windowStart.Equal(started) {
		t.Fatalf("window start = %s, want %s", windowStart, started)
	}
	if !lockedUntil.Valid || !lockedUntil.Time.Equal(now.Add(stepUpLockDuration)) {
		t.Fatalf("lockout = %+v, want lock until %s", lockedUntil, now.Add(stepUpLockDuration))
	}
}

func TestStepUpFailureWindowResetsAfterFifteenMinutes(t *testing.T) {
	started := time.Date(2026, time.November, 14, 12, 0, 0, 0, time.UTC)
	now := started.Add(stepUpFailureWindow)
	count, windowStart, lockedUntil := nextStepUpFailure(stepUpFailureLimit, started, now)
	if count != 1 || !windowStart.Equal(now) || lockedUntil.Valid {
		t.Fatalf("expired failure window = count %d, start %s, lock %+v", count, windowStart, lockedUntil)
	}
}

func TestStepUpLockoutMapsToRateLimit(t *testing.T) {
	mapped := mapError(errStepUpLocked)
	if mapped.Status != http.StatusTooManyRequests || mapped.Code != "step_up_locked" {
		t.Fatalf("mapped lockout = %+v, want 429 step_up_locked", mapped)
	}
}
