// Package operator answers who may use the admin console.
//
// This is deliberately not part of cryden at all — cryden's own
// store.User has no role or permission concept by design (see
// cryden's docs/design-decisions.md: authorization is a host
// decision, the engine only owns authentication mechanics). Which
// cryden users are console operators, and what role they hold, is a
// decision this csag layer makes on top, backed by its own table
// (migrations/003_operators.up.sql) keyed off cryden's own user id.
//
// It is its own package, not a file in package main, so both the
// running server (main.go) and the standalone bootstrap command
// (cmd/grant-operator) can use it without one importing the other's
// package main, which Go does not allow.
package operator

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var (
	ErrInvalidRole = errors.New("operator: role must be owner, admin, or viewer")
	ErrLastOwner   = errors.New("operator: cannot remove or demote the last owner")
)

type Operator struct {
	UserID    string
	Email     string
	Role      string
	CreatedAt time.Time
}

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// RoleFor returns the operator role for userID, and isOperator=false
// if userID holds no row at all — an ordinary end user, the common
// case. Never returns sql.ErrNoRows to the caller; that distinction
// is folded into the bool so callers don't need errors.Is for it.
func (s *Store) RoleFor(ctx context.Context, userID string) (role string, isOperator bool, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT role FROM operators WHERE user_id = $1`, userID).Scan(&role)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return role, true, nil
}

// Grant makes userID an operator with the given role, or updates their
// existing role — idempotent either way, so re-running a bootstrap
// script is always safe.
func (s *Store) Grant(ctx context.Context, userID, role string) error {
	if !ValidRole(role) {
		return ErrInvalidRole
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `LOCK TABLE operators IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return err
	}
	var current string
	err = tx.QueryRowContext(ctx, `SELECT role FROM operators WHERE user_id = $1`, userID).Scan(&current)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if current == "owner" && role != "owner" {
		if err := ensureAnotherOwner(ctx, tx); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO operators (user_id, role) VALUES ($1, $2)
		ON CONFLICT (user_id) DO UPDATE SET role = EXCLUDED.role
	`, userID, role); err != nil {
		return err
	}
	return tx.Commit()
}

func ValidRole(role string) bool {
	return role == "owner" || role == "admin" || role == "viewer"
}

func (s *Store) List(ctx context.Context) ([]Operator, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT o.user_id::text, u.email, o.role, o.created_at
		FROM operators o JOIN users u ON u.id = o.user_id
		ORDER BY o.created_at ASC, o.user_id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]Operator, 0)
	for rows.Next() {
		var item Operator
		if err := rows.Scan(&item.UserID, &item.Email, &item.Role, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.CreatedAt = item.CreatedAt.UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

// Revoke removes an operator. It is idempotent for a user with no operator row,
// but refuses to remove the final owner and lock out the installation.
func (s *Store) Revoke(ctx context.Context, userID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `LOCK TABLE operators IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return err
	}
	var role string
	err = tx.QueryRowContext(ctx, `SELECT role FROM operators WHERE user_id = $1`, userID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return tx.Commit()
	}
	if err != nil {
		return err
	}
	if role == "owner" {
		if err := ensureAnotherOwner(ctx, tx); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM operators WHERE user_id = $1`, userID); err != nil {
		return err
	}
	return tx.Commit()
}

func ensureAnotherOwner(ctx context.Context, tx *sql.Tx) error {
	var owners int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM operators WHERE role = 'owner'`).Scan(&owners); err != nil {
		return err
	}
	if owners <= 1 {
		return ErrLastOwner
	}
	return nil
}
