package operator

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/mail"
	"strings"
	"time"
)

var (
	ErrInvalidInvitation       = errors.New("operator invitation is invalid, expired, or already used")
	ErrInvitationEmailMismatch = errors.New("operator invitation is not intended for this account")
	ErrAlreadyOperator         = errors.New("this account is already an operator")
	ErrInvalidInvitationRole   = errors.New("operator invitations can grant admin or viewer only")
	ErrInvalidInvitationEmail  = errors.New("operator invitation requires a valid email address")
)

const InvitationLifetime = 7 * 24 * time.Hour

type Invitation struct {
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	Token     string    `json:"token,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CreateInvitation invalidates prior unused invitations for the same email.
// Only a SHA-256 digest is stored; the bearer token is returned once.
func (s *Store) CreateInvitation(ctx context.Context, email, role, createdBy string) (Invitation, error) {
	email, err := normalizeInviteEmail(email)
	if err != nil {
		return Invitation{}, err
	}
	if role != "admin" && role != "viewer" {
		return Invitation{}, ErrInvalidInvitationRole
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return Invitation{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	digest := sha256.Sum256([]byte(token))
	now := time.Now().UTC()
	expiresAt := now.Add(InvitationLifetime)
	var creator any
	if createdBy != "" {
		creator = createdBy
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Invitation{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `LOCK TABLE operator_invitations IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return Invitation{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE operator_invitations SET revoked_at=$2 WHERE lower(email)=lower($1) AND accepted_at IS NULL AND revoked_at IS NULL`, email, now); err != nil {
		return Invitation{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO operator_invitations (token_hash,email,role,created_by,created_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6)`, digest[:], email, role, creator, now, expiresAt); err != nil {
		return Invitation{}, err
	}
	if err := tx.Commit(); err != nil {
		return Invitation{}, err
	}
	return Invitation{Email: email, Role: role, Token: token, ExpiresAt: expiresAt}, nil
}

// AcceptInvitation atomically consumes a matching invitation and adds the
// already-authenticated Cryden user to the operator roster.
func (s *Store) AcceptInvitation(ctx context.Context, userID, email, token string) (Invitation, error) {
	if len(token) != 43 {
		return Invitation{}, ErrInvalidInvitation
	}
	if _, err := base64.RawURLEncoding.DecodeString(token); err != nil {
		return Invitation{}, ErrInvalidInvitation
	}
	email, err := normalizeInviteEmail(email)
	if err != nil {
		return Invitation{}, ErrInvitationEmailMismatch
	}
	digest := sha256.Sum256([]byte(token))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Invitation{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `LOCK TABLE operators IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return Invitation{}, err
	}

	var invitation Invitation
	var acceptedAt, revokedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT email,role,expires_at,accepted_at,revoked_at FROM operator_invitations WHERE token_hash=$1 FOR UPDATE`, digest[:]).Scan(&invitation.Email, &invitation.Role, &invitation.ExpiresAt, &acceptedAt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Invitation{}, ErrInvalidInvitation
	}
	if err != nil {
		return Invitation{}, err
	}
	if acceptedAt.Valid || revokedAt.Valid || !time.Now().Before(invitation.ExpiresAt) {
		return Invitation{}, ErrInvalidInvitation
	}
	if !strings.EqualFold(invitation.Email, email) {
		return Invitation{}, ErrInvitationEmailMismatch
	}
	var existing string
	err = tx.QueryRowContext(ctx, `SELECT role FROM operators WHERE user_id=$1`, userID).Scan(&existing)
	if err == nil {
		return Invitation{}, ErrAlreadyOperator
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Invitation{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO operators (user_id,role) VALUES ($1,$2)`, userID, invitation.Role); err != nil {
		return Invitation{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE operator_invitations SET accepted_at=now(),accepted_user_id=$2 WHERE token_hash=$1`, digest[:], userID); err != nil {
		return Invitation{}, err
	}
	if err := tx.Commit(); err != nil {
		return Invitation{}, err
	}
	invitation.Email = strings.ToLower(invitation.Email)
	return invitation, nil
}

func normalizeInviteEmail(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 320 {
		return "", ErrInvalidInvitationEmail
	}
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address != value || !strings.Contains(parsed.Address, "@") {
		return "", ErrInvalidInvitationEmail
	}
	return strings.ToLower(value), nil
}
