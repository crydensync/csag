package httpapi

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

const databaseSchema = "crydensync_auth"

// safeDatabaseColumns is a reviewed projection for the auth schema. New
// columns and tables are visible in the catalog but cannot be read until a
// projection is deliberately added here. Credential material and arbitrary
// JSON payloads therefore stay out of the browser by default.
var safeDatabaseColumns = map[string][]string{
	"schema_migrations":          {"name", "applied_at"},
	"users":                      {"id", "email", "failed_attempts", "locked_until", "created_at", "updated_at"},
	"sessions":                   {"id", "family_id", "user_id", "ip", "user_agent", "created_at", "revoked_at"},
	"audit_events":               {"id", "type", "user_id", "ip", "created_at"},
	"verification_tokens":        {"id", "user_id", "purpose", "new_email", "expires_at", "used_at", "created_at"},
	"oauth_identities":           {"id", "user_id", "provider", "email", "created_at"},
	"operators":                  {"user_id", "role", "created_at"},
	"totp_secrets":               {"user_id", "confirmed_at", "created_at"},
	"webauthn_credentials":       {"id", "user_id", "nickname", "created_at", "last_used_at"},
	"recovery_codes":             {"user_id", "used_at", "created_at"},
	"login_attempts":             {"id", "user_id", "ip", "user_agent", "outcome", "created_at"},
	"api_keys":                   {"id", "user_id", "name", "prefix", "scopes", "expires_at", "created_at", "last_used_at", "revoked_at"},
	"user_metadata":              {"user_id", "key", "created_at", "updated_at"},
	"webhook_deliveries":         {"id", "event_id", "event_type", "user_id", "ip", "status", "attempts", "response_code", "duration_ms", "created_at", "delivered_at"},
	"shipped_log_events":         {"id", "level", "message", "sink", "shipped_at"},
	"digest_runs":                {"id", "window_start", "window_end", "generated_at"},
	"settings":                   {"key", "updated_at"},
	"reviewed_anomalies":         {"event_id", "status", "reviewer_id", "updated_at"},
	"operator_stepup_challenges": {"user_id", "purpose", "expires_at", "created_at"},
	"operator_stepup_grants":     {"user_id", "purpose", "expires_at", "created_at"},
	"operator_stepup_lockouts":   {"user_id", "failure_count", "window_started_at", "locked_until", "updated_at"},
}

type DatabaseHandlers struct{ DB *sql.DB }

type databaseColumnDTO struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Nullable bool   `json:"nullable"`
	Readable bool   `json:"readable"`
}

type databaseTableDTO struct {
	Name    string              `json:"name"`
	Columns []databaseColumnDTO `json:"columns"`
}

type databaseCatalogDTO struct {
	Schema string             `json:"schema"`
	Tables []databaseTableDTO `json:"tables"`
}

type databaseRowsDTO struct {
	Schema  string           `json:"schema"`
	Table   string           `json:"table"`
	Columns []string         `json:"columns"`
	Rows    []map[string]any `json:"rows"`
	Total   int64            `json:"total"`
	Limit   int              `json:"limit"`
	Offset  int              `json:"offset"`
}

type catalogColumn struct {
	name, dataType string
	nullable       bool
}

func (h *DatabaseHandlers) ListTables(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.DB == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}
	schema, tables, err := h.catalog(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	out := make([]databaseTableDTO, 0, len(tables))
	for name, columns := range tables {
		allowed := makeColumnSet(safeDatabaseColumns[name])
		columnDTOs := make([]databaseColumnDTO, 0, len(columns))
		for _, column := range columns {
			_, readable := allowed[column.name]
			columnDTOs = append(columnDTOs, databaseColumnDTO{
				Name: column.name, Type: column.dataType, Nullable: column.nullable, Readable: readable,
			})
		}
		out = append(out, databaseTableDTO{Name: name, Columns: columnDTOs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeData(w, http.StatusOK, databaseCatalogDTO{Schema: schema, Tables: out})
}

func (h *DatabaseHandlers) ReadTable(w http.ResponseWriter, r *http.Request, table string) {
	if h == nil || h.DB == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}
	limit, err := queryInt(r, "limit", 25, 1, 100)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	offset, err := queryInt(r, "offset", 0, 0, 100000)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	schema, tables, err := h.catalog(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	columns, exists := tables[table]
	if !exists {
		writeDatabaseNotFound(w, "database_table_not_found", "that table is not in the active auth schema")
		return
	}
	allowed := makeColumnSet(safeDatabaseColumns[table])
	selected := make([]string, 0, len(allowed))
	present := make(map[string]bool, len(columns))
	for _, column := range columns {
		present[column.name] = true
	}
	for _, name := range safeDatabaseColumns[table] {
		if present[name] {
			selected = append(selected, name)
		}
	}
	if len(selected) == 0 {
		writeDatabaseNotFound(w, "database_table_not_browsable", "this table has no reviewed, non-sensitive columns available to display")
		return
	}

	quotedTable := quoteIdentifier(table)
	quotedSchema := quoteIdentifier(schema)
	var total int64
	if err := h.DB.QueryRowContext(r.Context(), `SELECT count(*) FROM `+quotedSchema+`.`+quotedTable).Scan(&total); err != nil {
		writeErr(w, err)
		return
	}
	quotedColumns := make([]string, len(selected))
	for i, column := range selected {
		quotedColumns[i] = quoteIdentifier(column)
	}
	query := fmt.Sprintf("SELECT %s FROM %s.%s ORDER BY 1 LIMIT $1 OFFSET $2",
		strings.Join(quotedColumns, ", "), quotedSchema, quotedTable)
	rows, err := h.DB.QueryContext(r.Context(), query, limit, offset)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()
	result := make([]map[string]any, 0, limit)
	for rows.Next() {
		values := make([]any, len(selected))
		destinations := make([]any, len(selected))
		for i := range values {
			destinations[i] = &values[i]
		}
		if err := rows.Scan(destinations...); err != nil {
			writeErr(w, err)
			return
		}
		item := make(map[string]any, len(selected))
		for i, value := range values {
			item[selected[i]] = databaseJSONValue(value)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, databaseRowsDTO{
		Schema: schema, Table: table, Columns: selected, Rows: result, Total: total, Limit: limit, Offset: offset,
	})
}

func (h *DatabaseHandlers) catalog(r *http.Request) (string, map[string][]catalogColumn, error) {
	// Use the auth schema explicitly. Deployments can have a search_path such
	// as "$user", public, so current_schema() is not a reliable indicator of
	// which schema CSAG owns or should expose here.
	schema := databaseSchema
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT table_name, column_name, data_type, is_nullable
		FROM information_schema.columns
		WHERE table_schema = $1
		ORDER BY table_name, ordinal_position`, schema)
	if err != nil {
		return "", nil, err
	}
	defer rows.Close()
	tables := make(map[string][]catalogColumn)
	for rows.Next() {
		var table, name, dataType, nullable string
		if err := rows.Scan(&table, &name, &dataType, &nullable); err != nil {
			return "", nil, err
		}
		tables[table] = append(tables[table], catalogColumn{
			name: name, dataType: dataType, nullable: nullable == "YES",
		})
	}
	if err := rows.Err(); err != nil {
		return "", nil, err
	}
	return schema, tables, nil
}

func makeColumnSet(columns []string) map[string]struct{} {
	out := make(map[string]struct{}, len(columns))
	for _, column := range columns {
		out[column] = struct{}{}
	}
	return out
}

func quoteIdentifier(identifier string) string {
	return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"`
}

func databaseJSONValue(value any) any {
	switch value := value.(type) {
	case []byte:
		return string(value)
	case time.Time:
		return value.UTC().Format(time.RFC3339Nano)
	case sql.NullString:
		if !value.Valid {
			return nil
		}
		return value.String
	case sql.NullInt64:
		if !value.Valid {
			return nil
		}
		return value.Int64
	case sql.NullBool:
		if !value.Valid {
			return nil
		}
		return value.Bool
	default:
		return value
	}
}

func writeDatabaseNotFound(w http.ResponseWriter, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}
