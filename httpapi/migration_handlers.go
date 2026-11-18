package httpapi

import (
	"database/sql"
	"net/http"
	"sort"
)

type MigrationHandlers struct {
	DB       *sql.DB
	Expected []string
}

type appliedMigrationDTO struct {
	Name      string `json:"name"`
	AppliedAt string `json:"applied_at"`
}

type migrationStatusDTO struct {
	Schema  string                `json:"schema"`
	Current string                `json:"current"`
	Applied []appliedMigrationDTO `json:"applied"`
	Pending []string              `json:"pending"`
}

// Status reads the active CSAG database migration tracker without changing it.
func (h *MigrationHandlers) Status(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.DB == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}
	rows, err := h.DB.QueryContext(r.Context(), `SELECT name, applied_at FROM crydensync_auth.schema_migrations ORDER BY name`)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()
	applied := make([]appliedMigrationDTO, 0)
	seen := make(map[string]bool)
	for rows.Next() {
		var migration appliedMigrationDTO
		if err := rows.Scan(&migration.Name, &migration.AppliedAt); err != nil {
			writeErr(w, err)
			return
		}
		applied = append(applied, migration)
		seen[migration.Name] = true
	}
	if err := rows.Err(); err != nil {
		writeErr(w, err)
		return
	}
	expected := append([]string(nil), h.Expected...)
	sort.Strings(expected)
	pending := make([]string, 0)
	for _, name := range expected {
		if !seen[name] {
			pending = append(pending, name)
		}
	}
	current := ""
	if len(applied) > 0 {
		current = applied[len(applied)-1].Name
	}
	writeData(w, http.StatusOK, migrationStatusDTO{Schema: "crydensync_auth", Current: current, Applied: applied, Pending: pending})
}
