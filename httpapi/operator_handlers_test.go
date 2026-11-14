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
	for _, purpose := range []string{"operator_role_change", "operator_remove", "operator_session_revoke", "operator_passkey_remove", "secret_reveal", "secret_mutation"} {
		if !validStepUpPurpose(purpose) {
			t.Errorf("%q should be accepted", purpose)
		}
	}
	for _, purpose := range []string{"", "session_revoke", "operator_invite"} {
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

	secretAction := httptest.NewRecorder()
	if !h.authorizeStepUpPurpose(secretAction, r, "secret_mutation") {
		t.Fatalf("admin was refused a secret step-up: %s", secretAction.Body.String())
	}
}
