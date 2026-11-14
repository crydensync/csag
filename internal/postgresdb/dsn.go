// Package postgresdb contains connection helpers shared by the API and its
// standalone database administration commands.
package postgresdb

import (
	"net/url"
	"strings"
)

const AuthSchema = "crydensync_auth"

// DSNWithSearchPath pins every pooled PostgreSQL connection to the requested
// schema. Applying SET after opening a database would affect only one pooled
// connection, so the setting belongs in the DSN.
func DSNWithSearchPath(dsn, schema string) string {
	if strings.Contains(dsn, "://") {
		parsed, err := url.Parse(dsn)
		if err == nil {
			query := parsed.Query()
			query.Set("search_path", schema)
			parsed.RawQuery = query.Encode()
			return parsed.String()
		}
	}
	return strings.TrimSpace(dsn) + " search_path=" + schema
}
