package postgresdb

import (
	"net/url"
	"strings"
	"testing"
)

func TestDSNWithSearchPathURL(t *testing.T) {
	dsn := DSNWithSearchPath("postgres://user:password@localhost/auth?sslmode=disable&search_path=public", "crydensync_auth")
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse rewritten DSN: %v", err)
	}
	if got := parsed.Query().Get("search_path"); got != "crydensync_auth" {
		t.Errorf("search_path = %q, want crydensync_auth", got)
	}
	if got := parsed.Query().Get("sslmode"); got != "disable" {
		t.Errorf("sslmode = %q, want disable", got)
	}
}

func TestDSNWithSearchPathKeyword(t *testing.T) {
	dsn := DSNWithSearchPath("host=localhost user=csag dbname=auth", "crydensync_auth")
	if !strings.HasSuffix(dsn, "search_path=crydensync_auth") {
		t.Errorf("keyword DSN = %q, want the search_path appended", dsn)
	}
}
