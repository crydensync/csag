package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/lib/pq"
)

// SystemHandlers reports only aggregate deployment state. It does not expose
// connection strings, hostnames, environment values, or per-user records.
type SystemHandlers struct {
	DB             *sql.DB
	MigrationNames []string
}

type systemStatsDTO struct {
	Users          int64 `json:"users"`
	ActiveSessions int64 `json:"active_sessions"`
	Operators      int64 `json:"operators"`
	ActiveAPIKeys  int64 `json:"active_api_keys"`
}

type migrationRecordDTO struct {
	Name      string `json:"name"`
	AppliedAt string `json:"applied_at"`
}

type migrationStatusDTO struct {
	Current *string              `json:"current"`
	Applied []migrationRecordDTO `json:"applied"`
	Pending []string             `json:"pending"`
	Unknown []string             `json:"unknown"`
}

type systemCheckDTO struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type doctorDTO struct {
	Status    string           `json:"status"`
	CheckedAt time.Time        `json:"checked_at"`
	Checks    []systemCheckDTO `json:"checks"`
}

// Stats returns aggregate counts for the System Status screen.
func (h *SystemHandlers) Stats(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}
	queries := []struct {
		query string
		value *int64
	}{
		{`SELECT COUNT(*) FROM users`, nil},
		{`SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL`, nil},
		{`SELECT COUNT(*) FROM operators`, nil},
		{`SELECT COUNT(*) FROM api_keys WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`, nil},
	}
	var result systemStatsDTO
	queries[0].value = &result.Users
	queries[1].value = &result.ActiveSessions
	queries[2].value = &result.Operators
	queries[3].value = &result.ActiveAPIKeys
	for _, item := range queries {
		if err := h.DB.QueryRowContext(r.Context(), item.query).Scan(item.value); err != nil {
			writeErr(w, err)
			return
		}
	}
	writeData(w, http.StatusOK, result)
}

// Migrations reports recorded, pending, and unexpected migration names in the
// auth schema. The embedded expected order is supplied by main.go.
func (h *SystemHandlers) Migrations(w http.ResponseWriter, r *http.Request) {
	status, err := h.migrationStatus(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, status)
}

// Doctor reports whether the database answers and whether the schema matches
// this binary. It returns a diagnostic answer even when a check is degraded;
// details are fixed, non-sensitive descriptions rather than driver errors.
func (h *SystemHandlers) Doctor(w http.ResponseWriter, r *http.Request) {
	result := doctorDTO{Status: "healthy", CheckedAt: time.Now().UTC(), Checks: make([]systemCheckDTO, 0, 2)}
	if h.DB == nil {
		result.Status = "degraded"
		result.Checks = append(result.Checks, systemCheckDTO{Name: "database", Status: "unknown", Detail: "Database status is not configured."})
		result.Checks = append(result.Checks, systemCheckDTO{Name: "migrations", Status: "unknown", Detail: "Migration status is unavailable."})
		writeData(w, http.StatusOK, result)
		return
	}
	if err := h.DB.PingContext(r.Context()); err != nil {
		result.Status = "degraded"
		result.Checks = append(result.Checks, systemCheckDTO{Name: "database", Status: "failed", Detail: "The authentication database did not respond to a ping."})
		result.Checks = append(result.Checks, systemCheckDTO{Name: "migrations", Status: "unknown", Detail: "Migration status could not be read."})
		writeData(w, http.StatusOK, result)
		return
	}
	result.Checks = append(result.Checks, systemCheckDTO{Name: "database", Status: "healthy", Detail: "The authentication database answered."})
	migrations, err := h.migrationStatus(r.Context())
	if err != nil {
		result.Status = "degraded"
		result.Checks = append(result.Checks, systemCheckDTO{Name: "migrations", Status: "unknown", Detail: "Migration status could not be read."})
		writeData(w, http.StatusOK, result)
		return
	}
	if len(migrations.Pending) > 0 || len(migrations.Unknown) > 0 {
		result.Status = "degraded"
		result.Checks = append(result.Checks, systemCheckDTO{Name: "migrations", Status: "attention", Detail: "The database migration records do not match this API build."})
	} else {
		result.Checks = append(result.Checks, systemCheckDTO{Name: "migrations", Status: "healthy", Detail: "All migrations in this API build are recorded."})
	}
	writeData(w, http.StatusOK, result)
}

func (h *SystemHandlers) migrationStatus(ctx context.Context) (migrationStatusDTO, error) {
	if h.DB == nil {
		return migrationStatusDTO{}, errAdminStoresUnavailable
	}
	rows, err := h.DB.QueryContext(ctx, `SELECT name, applied_at FROM schema_migrations`)
	if err != nil {
		var postgresErr *pq.Error
		if errors.As(err, &postgresErr) && postgresErr.Code == "42P01" {
			return buildMigrationStatus(h.MigrationNames, map[string]string{}), nil
		}
		return migrationStatusDTO{}, err
	}
	defer rows.Close()
	byName := make(map[string]string)
	for rows.Next() {
		var name, appliedAt string
		if err := rows.Scan(&name, &appliedAt); err != nil {
			return migrationStatusDTO{}, err
		}
		byName[name] = appliedAt
	}
	if err := rows.Err(); err != nil {
		return migrationStatusDTO{}, err
	}
	return buildMigrationStatus(h.MigrationNames, byName), nil
}

func buildMigrationStatus(expected []string, recorded map[string]string) migrationStatusDTO {
	result := migrationStatusDTO{
		Applied: make([]migrationRecordDTO, 0, len(expected)),
		Pending: make([]string, 0),
		Unknown: make([]string, 0),
	}
	known := make(map[string]struct{}, len(expected))
	for _, name := range expected {
		known[name] = struct{}{}
		if appliedAt, ok := recorded[name]; ok {
			result.Applied = append(result.Applied, migrationRecordDTO{Name: name, AppliedAt: appliedAt})
			current := name
			result.Current = &current
		} else {
			result.Pending = append(result.Pending, name)
		}
	}
	for name := range recorded {
		if _, ok := known[name]; !ok {
			result.Unknown = append(result.Unknown, name)
		}
	}
	sort.Strings(result.Unknown)
	return result
}
