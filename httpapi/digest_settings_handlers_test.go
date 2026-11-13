package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crydensync/api/config"
	"github.com/crydensync/api/digest"
	"github.com/crydensync/api/settings"
)

type digestScheduleResponse struct {
	Data struct {
		Enabled           bool     `json:"enabled"`
		DayOfWeek         string   `json:"day_of_week"`
		Time              string   `json:"time"`
		Timezone          string   `json:"timezone"`
		Recipients        []string `json:"recipients"`
		DeliveryEnabled   bool     `json:"delivery_enabled"`
		DeliveryAvailable bool     `json:"delivery_available"`
		IntervalHours     int      `json:"interval_hours"`
	} `json:"data"`
}

type digestScheduleSender struct{}

func (digestScheduleSender) SendDigest(context.Context, string, string, string) error { return nil }

func digestScheduleFixture(t *testing.T, sender digest.DeliverySender) (digestFixture, *digest.Runtime) {
	t.Helper()
	f := newDigestFixture(t)
	store := settings.NewMemoryStore()
	runtime, err := digest.NewRuntime(context.Background(), store, digest.DefaultScheduleSettings())
	if err != nil {
		t.Fatalf("digest.NewRuntime: %v", err)
	}
	f.router = NewRouter(Deps{
		Engine: f.engine, Audit: f.audit, Digests: f.store, Config: config.Config{},
		DigestSchedule: runtime, DigestSender: sender,
	})
	return f, runtime
}

func TestDigestScheduleSettingsReadAndPersist(t *testing.T) {
	f, runtime := digestScheduleFixture(t, nil)
	read := httptest.NewRecorder()
	f.router.ServeHTTP(read, httptest.NewRequest(http.MethodGet, "/v1/admin/settings/digest", nil))
	// The route is admin gated, so the same request without a token is refused.
	if read.Code != http.StatusUnauthorized {
		t.Fatalf("GET without auth = %d, want 401", read.Code)
	}

	read = httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/admin/settings/digest", nil)
	request.Header.Set("Authorization", "Bearer "+f.adminToken)
	f.router.ServeHTTP(read, request)
	if read.Code != http.StatusOK {
		t.Fatalf("GET settings = %d, want 200 (body %s)", read.Code, read.Body.String())
	}
	var initial digestScheduleResponse
	if err := json.Unmarshal(read.Body.Bytes(), &initial); err != nil {
		t.Fatal(err)
	}
	if initial.Data.DeliveryAvailable {
		t.Fatal("delivery_available = true without a host sender")
	}
	if initial.Data.DayOfWeek != "monday" || initial.Data.Time != "09:00" || initial.Data.Timezone != "UTC" {
		t.Fatalf("default schedule = %+v", initial.Data)
	}

	body := `{"enabled":true,"day_of_week":"friday","time":"16:30","timezone":"Africa/Casablanca","recipients":["security@example.com"],"delivery_enabled":false}`
	put := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPut, "/v1/admin/settings/digest", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+f.adminToken)
	f.router.ServeHTTP(put, request)
	if put.Code != http.StatusOK {
		t.Fatalf("PUT settings = %d, want 200 (body %s)", put.Code, put.Body.String())
	}
	got := runtime.Snapshot()
	if !got.Enabled || got.DayOfWeek != "friday" || got.Time != "16:30" || got.Timezone != "Africa/Casablanca" || got.Recipients[0] != "security@example.com" {
		t.Fatalf("active settings = %+v, want the saved weekly schedule", got)
	}
}

func TestDigestScheduleSettingsRefuseUnavailableDeliveryAndInvalidData(t *testing.T) {
	f, runtime := digestScheduleFixture(t, nil)
	for name, body := range map[string]string{
		"malformed timezone": `{"enabled":true,"day_of_week":"friday","time":"09:00","timezone":"Mars/Olympus","recipients":[],"delivery_enabled":false}`,
		"invalid email":      `{"enabled":true,"day_of_week":"friday","time":"09:00","timezone":"UTC","recipients":["bad"],"delivery_enabled":false}`,
		"extra field":        `{"enabled":false,"day_of_week":"friday","time":"09:00","timezone":"UTC","recipients":[],"delivery_enabled":false,"smtp_password":"secret"}`,
	} {
		t.Run(name, func(t *testing.T) {
			rec := putDigestSchedule(t, f, body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("PUT = %d, want 400 (body %s)", rec.Code, rec.Body.String())
			}
		})
	}

	body := `{"enabled":true,"day_of_week":"friday","time":"09:00","timezone":"UTC","recipients":["security@example.com"],"delivery_enabled":true}`
	rec := putDigestSchedule(t, f, body)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("PUT with delivery enabled = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec); got.Code != "digest_delivery_not_configured" {
		t.Fatalf("error code = %q, want digest_delivery_not_configured", got.Code)
	}
	if runtime.Snapshot().Enabled {
		t.Fatal("settings changed despite delivery refusal")
	}
}

func TestDigestScheduleCanEnableDeliveryWhenHostSenderExists(t *testing.T) {
	f, runtime := digestScheduleFixture(t, digestScheduleSender{})
	body := `{"enabled":true,"day_of_week":"friday","time":"09:00","timezone":"UTC","recipients":["security@example.com"],"delivery_enabled":true}`
	rec := putDigestSchedule(t, f, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT with sender = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if !runtime.Snapshot().DeliveryEnabled {
		t.Fatal("delivery_enabled was not published after save")
	}
	var response digestScheduleResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Data.DeliveryAvailable {
		t.Fatal("delivery_available = false with a host sender")
	}
}

func putDigestSchedule(t *testing.T, f digestFixture, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/v1/admin/settings/digest", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+f.adminToken)
	f.router.ServeHTTP(rec, request)
	return rec
}
