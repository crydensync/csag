package httpapi

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"testing"

	_ "modernc.org/sqlite"
)

func TestMigrationStatusShowsAppliedAndPending(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, statement := range []string{
		`ATTACH DATABASE ':memory:' AS crydensync_auth`,
		`CREATE TABLE crydensync_auth.schema_migrations (name TEXT NOT NULL, applied_at TEXT NOT NULL)`,
		`INSERT INTO crydensync_auth.schema_migrations (name, applied_at) VALUES ('001_initial_schema.up.sql', '2026-11-01T12:00:00Z')`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("execute %q: %v", statement, err)
		}
	}

	recorder := httptest.NewRecorder()
	(&MigrationHandlers{DB: db, Expected: []string{
		"001_initial_schema.up.sql",
		"002_oauth_identities.up.sql",
	}}).Status(recorder, httptest.NewRequest("GET", "/v1/admin/database/migrations", nil))
	if recorder.Code != 200 {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Data migrationStatusDTO `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.Schema != "crydensync_auth" || response.Data.Current != "001_initial_schema.up.sql" {
		t.Fatalf("migration status = %+v", response.Data)
	}
	if len(response.Data.Applied) != 1 || len(response.Data.Pending) != 1 || response.Data.Pending[0] != "002_oauth_identities.up.sql" {
		t.Fatalf("migration status = %+v", response.Data)
	}
}
