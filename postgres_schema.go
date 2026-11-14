package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"

	"github.com/crydensync/api/internal/postgresdb"
)

const postgresAuthSchema = postgresdb.AuthSchema

// postgresAuthTables is every application table this API and cryden's
// Postgres stores own. The migration tracker is handled separately so its
// CSAG rows can be separated from product rows in a shared public tracker.
var postgresAuthTables = []string{
	"users",
	"sessions",
	"audit_events",
	"verification_tokens",
	"oauth_identities",
	"operators",
	"totp_secrets",
	"webauthn_credentials",
	"recovery_codes",
	"login_attempts",
	"api_keys",
	"user_metadata",
	"webhook_deliveries",
	"shipped_log_events",
	"digest_runs",
	"settings",
	"reviewed_anomalies",
	"operator_stepup_challenges",
	"operator_stepup_grants",
	"operator_stepup_lockouts",
}

// preparePostgresSchema creates the private namespace and moves a known
// legacy CSAG schema from public without copying or dropping rows. Normal
// startup only moves a schema carrying CSAG's migration marker. The
// explicit --baseline command may also move an untracked legacy schema,
// because the operator has asserted that the existing tables belong to
// this API.
func preparePostgresSchema(ctx context.Context, db *sql.DB, allowUntrackedLegacy bool) error {
	if _, err := db.ExecContext(ctx, `CREATE SCHEMA IF NOT EXISTS crydensync_auth`); err != nil {
		return fmt.Errorf("creating PostgreSQL schema %s: %w", postgresAuthSchema, err)
	}

	var authTracker, publicTracker bool
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('crydensync_auth.schema_migrations') IS NOT NULL`).Scan(&authTracker); err != nil {
		return fmt.Errorf("checking %s migration tracker: %w", postgresAuthSchema, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('public.schema_migrations') IS NOT NULL`).Scan(&publicTracker); err != nil {
		return fmt.Errorf("checking public migration tracker: %w", err)
	}
	if authTracker && publicTracker {
		return errors.New("both public.schema_migrations and crydensync_auth.schema_migrations exist; refusing to guess which schema contains the active CSAG data")
	}

	legacyCSAG := false
	if publicTracker {
		if err := db.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM public.schema_migrations
				WHERE name = '001_initial_schema.up.sql'
			)
		`).Scan(&legacyCSAG); err != nil {
			return fmt.Errorf("checking the legacy CSAG migration marker: %w", err)
		}
	}
	if !legacyCSAG && !allowUntrackedLegacy {
		return nil
	}
	if authTracker {
		return errors.New("the CSAG migration tracker already exists in crydensync_auth, but legacy tables remain in public; refusing to merge schemas automatically")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("starting PostgreSQL schema move: %w", err)
	}
	defer tx.Rollback()

	if allowUntrackedLegacy && !legacyCSAG {
		var coreTables int
		if err := tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM information_schema.tables
			WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
			AND table_name IN ('users', 'sessions', 'audit_events')
		`).Scan(&coreTables); err != nil {
			return fmt.Errorf("checking for an untracked legacy CSAG schema: %w", err)
		}
		if coreTables != 3 {
			return errors.New("--baseline requires the existing users, sessions and audit_events tables in public")
		}
	}
	var migrationNames []string
	if legacyCSAG {
		migrationFS, err := fs.Sub(postgresMigrations, postgresMigrationDir)
		if err != nil {
			return fmt.Errorf("opening embedded PostgreSQL migrations: %w", err)
		}
		migrationNames, err = upMigrationNames(migrationFS)
		if err != nil {
			return fmt.Errorf("listing PostgreSQL migrations: %w", err)
		}
	}

	for _, table := range postgresAuthTables {
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, "public."+table).Scan(&exists); err != nil {
			return fmt.Errorf("checking public.%s: %w", table, err)
		}
		if !exists {
			continue
		}
		var targetExists bool
		if err := tx.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, postgresAuthSchema+"."+table).Scan(&targetExists); err != nil {
			return fmt.Errorf("checking %s.%s: %w", postgresAuthSchema, table, err)
		}
		if targetExists {
			return fmt.Errorf("both public.%s and %s.%s exist; refusing to overwrite either table", table, postgresAuthSchema, table)
		}
		if _, err := tx.ExecContext(ctx, `ALTER TABLE public."`+table+`" SET SCHEMA crydensync_auth`); err != nil {
			return fmt.Errorf("moving public.%s into %s: %w", table, postgresAuthSchema, err)
		}
	}

	if legacyCSAG {
		if _, err := tx.ExecContext(ctx, createMigrationTableSQL); err != nil {
			return fmt.Errorf("creating the CSAG migration tracker in %s: %w", postgresAuthSchema, err)
		}
		for _, name := range migrationNames {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO crydensync_auth.schema_migrations (name, applied_at)
				SELECT name, applied_at FROM public.schema_migrations WHERE name = $1
				ON CONFLICT (name) DO NOTHING`, name); err != nil {
				return fmt.Errorf("copying CSAG migration marker %s: %w", name, err)
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM public.schema_migrations WHERE name = $1`, name); err != nil {
				return fmt.Errorf("removing moved CSAG migration marker %s: %w", name, err)
			}
		}
		var remainingMarkers int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM public.schema_migrations`).Scan(&remainingMarkers); err != nil {
			return fmt.Errorf("checking for non-CSAG migration markers in public: %w", err)
		}
		if remainingMarkers == 0 {
			if _, err := tx.ExecContext(ctx, `DROP TABLE public.schema_migrations`); err != nil {
				return fmt.Errorf("removing the empty legacy CSAG migration tracker: %w", err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing PostgreSQL schema move: %w", err)
	}
	return nil
}
