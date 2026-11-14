package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func openSystemTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	for _, statement := range []string{
		`CREATE TABLE users (id TEXT PRIMARY KEY)`,
		`CREATE TABLE sessions (id TEXT PRIMARY KEY, revoked_at TEXT)`,
		`CREATE TABLE operators (user_id TEXT PRIMARY KEY)`,
		`CREATE TABLE api_keys (id TEXT PRIMARY KEY, revoked_at TEXT, expires_at TEXT)`,
		`CREATE TABLE schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("create system test schema: %v", err)
		}
	}
	return db
}

func TestSystemStatsReturnOnlyAggregateCounts(t *testing.T) {
	db := openSystemTestDB(t)
	for _, statement := range []string{
		`INSERT INTO users VALUES ('user-1'), ('user-2')`,
		`INSERT INTO sessions VALUES ('session-1', NULL), ('session-2', 'revoked')`,
		`INSERT INTO operators VALUES ('user-1')`,
		`INSERT INTO api_keys VALUES ('key-1', NULL, NULL), ('key-2', 'revoked', NULL)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}

	rec := httptest.NewRecorder()
	(&SystemHandlers{DB: db}).Stats(rec, httptest.NewRequest(http.MethodGet, "/v1/admin/stats", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Data systemStatsDTO `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data != (systemStatsDTO{Users: 2, ActiveSessions: 1, Operators: 1, ActiveAPIKeys: 1}) {
		t.Fatalf("stats = %+v", response.Data)
	}
}

func TestSystemMigrationStatusUsesEmbeddedOrderAndReportsUnknownNames(t *testing.T) {
	now := time.Date(2026, time.November, 15, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
	recorded := map[string]string{
		"001_initial_schema.up.sql": now,
		"003_operators.up.sql":      now,
		"999_unrecognized.up.sql":   now,
	}
	status := buildMigrationStatus([]string{
		"001_initial_schema.up.sql",
		"002_second.up.sql",
		"003_operators.up.sql",
	}, recorded)
	if status.Current == nil || *status.Current != "003_operators.up.sql" {
		t.Fatalf("current = %v", status.Current)
	}
	if len(status.Applied) != 2 || status.Applied[0].Name != "001_initial_schema.up.sql" || status.Applied[1].Name != "003_operators.up.sql" {
		t.Fatalf("applied = %+v", status.Applied)
	}
	if len(status.Pending) != 1 || status.Pending[0] != "002_second.up.sql" {
		t.Fatalf("pending = %v", status.Pending)
	}
	if len(status.Unknown) != 1 || status.Unknown[0] != "999_unrecognized.up.sql" {
		t.Fatalf("unknown = %v", status.Unknown)
	}
	if _, ok := recorded["001_initial_schema.up.sql"]; !ok {
		t.Fatal("builder mutated the recorded input")
	}
}

func TestSystemDoctorReportsMigrationAttentionWithoutLeakingErrors(t *testing.T) {
	db := openSystemTestDB(t)
	if _, err := db.Exec(`INSERT INTO schema_migrations VALUES ('001_initial_schema.up.sql', '2026-11-15T12:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	h := &SystemHandlers{DB: db, MigrationNames: []string{"001_initial_schema.up.sql", "002_pending.up.sql"}}
	rec := httptest.NewRecorder()
	h.Doctor(rec, httptest.NewRequest(http.MethodGet, "/v1/admin/doctor", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Data doctorDTO `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.Status != "degraded" || len(response.Data.Checks) != 2 || response.Data.Checks[1].Status != "attention" {
		t.Fatalf("doctor = %+v", response.Data)
	}
	if response.Data.Checks[1].Detail != "The database migration records do not match this API build." {
		t.Fatalf("migration detail exposed unexpected data: %+v", response.Data.Checks[1])
	}
}

func TestSystemMigrationStatusRejectsMissingDatabase(t *testing.T) {
	h := &SystemHandlers{}
	_, err := h.migrationStatus(context.Background())
	if err == nil {
		t.Fatal("expected missing database error")
	}
}
