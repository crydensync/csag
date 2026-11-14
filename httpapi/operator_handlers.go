package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/crydensync/api/config"
	"github.com/crydensync/api/operator"
	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var errStepUpRequired = errors.New("fresh WebAuthn step-up required")
var errLastOperatorPasskey = errors.New("the last operator passkey cannot be removed")

type OperatorHandlers struct {
	Store interface {
		List(context.Context) ([]operator.Operator, error)
	}
	DB       *sql.DB
	Engine   *cryden.Engine
	Config   config.Config
	Users    store.UserStore
	Passkeys store.WebAuthnCredentialStore
	Sessions store.SessionStore
	Audit    store.AuditStore
}

type stepUpUser struct {
	id, email   string
	credentials []webauthn.Credential
}

func (u *stepUpUser) WebAuthnID() []byte                         { return []byte(u.id) }
func (u *stepUpUser) WebAuthnName() string                       { return u.email }
func (u *stepUpUser) WebAuthnDisplayName() string                { return u.email }
func (u *stepUpUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func (h *OperatorHandlers) webAuthn() (*webauthn.WebAuthn, error) {
	if h.Config.WebAuthnRPID == "" || h.Config.WebAuthnRPDisplayName == "" || len(h.Config.WebAuthnRPOrigins) == 0 {
		return nil, errStepUpRequired
	}
	return webauthn.New(&webauthn.Config{RPDisplayName: h.Config.WebAuthnRPDisplayName, RPID: h.Config.WebAuthnRPID, RPOrigins: h.Config.WebAuthnRPOrigins})
}

func (h *OperatorHandlers) user(ctx context.Context, id string) (*stepUpUser, error) {
	if h.Users == nil || h.Passkeys == nil {
		return nil, errStepUpRequired
	}
	u, err := h.Users.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	stored, err := h.Passkeys.ListByUser(ctx, id)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthn.Credential, 0, len(stored))
	for _, item := range stored {
		var c webauthn.Credential
		if err := json.Unmarshal(item.CredentialData, &c); err != nil {
			return nil, err
		}
		creds = append(creds, c)
	}
	if len(creds) == 0 {
		return nil, errStepUpRequired
	}
	return &stepUpUser{id: u.ID, email: u.Email, credentials: creds}, nil
}

type beginStepUpRequest struct {
	Purpose string `json:"purpose"`
}

func (h *OperatorHandlers) BeginStepUp(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
		writeErr(w, errStepUpRequired)
		return
	}
	var req beginStepUpRequest
	if json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req) != nil || !validStepUpPurpose(req.Purpose) {
		writeBadRequest(w, "a valid operator step-up purpose is required")
		return
	}
	if !h.authorizeStepUpPurpose(w, r, req.Purpose) {
		return
	}
	userID := r.Context().Value(userIDContextKey).(string)
	_, _ = h.DB.ExecContext(r.Context(), `DELETE FROM operator_stepup_challenges WHERE expires_at <= now()`)
	_, _ = h.DB.ExecContext(r.Context(), `DELETE FROM operator_stepup_grants WHERE expires_at <= now()`)
	user, err := h.user(r.Context(), userID)
	if err != nil {
		writeErr(w, err)
		return
	}
	wa, err := h.webAuthn()
	if err != nil {
		writeErr(w, err)
		return
	}
	options, session, err := wa.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		writeErr(w, err)
		return
	}
	state, err := json.Marshal(session)
	if err != nil {
		writeErr(w, err)
		return
	}
	ceremony, err := randomStepUpToken()
	if err != nil {
		writeErr(w, err)
		return
	}
	accessHash := sha256.Sum256([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
	if _, err = h.DB.ExecContext(r.Context(), `INSERT INTO operator_stepup_challenges (token_hash,user_id,access_token_hash,purpose,session_data,expires_at) VALUES ($1,$2,$3,$4,$5,now()+interval '60 seconds')`, hashStepUp(ceremony), userID, accessHash[:], req.Purpose, state); err != nil {
		writeErr(w, err)
		return
	}
	optionsJSON, err := json.Marshal(options)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]any{"public_key": json.RawMessage(optionsJSON), "ceremony_token": ceremony})
}

type finishStepUpRequest struct {
	Purpose       string          `json:"purpose"`
	CeremonyToken string          `json:"ceremony_token"`
	Credential    json.RawMessage `json:"credential"`
}

func (h *OperatorHandlers) FinishStepUp(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
		writeErr(w, errStepUpRequired)
		return
	}
	var req finishStepUpRequest
	if json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req) != nil || !validStepUpPurpose(req.Purpose) || len(req.CeremonyToken) < 32 || len(req.Credential) == 0 {
		writeBadRequest(w, "invalid operator step-up response")
		return
	}
	if !h.authorizeStepUpPurpose(w, r, req.Purpose) {
		return
	}
	userID := r.Context().Value(userIDContextKey).(string)
	accessHash := sha256.Sum256([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
	var state []byte
	err := h.DB.QueryRowContext(r.Context(), `DELETE FROM operator_stepup_challenges WHERE token_hash=$1 AND user_id=$2 AND access_token_hash=$3 AND purpose=$4 AND expires_at>now() RETURNING session_data`, hashStepUp(req.CeremonyToken), userID, accessHash[:], req.Purpose).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, errStepUpRequired)
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	var session webauthn.SessionData
	if json.Unmarshal(state, &session) != nil {
		writeErr(w, errStepUpRequired)
		return
	}
	user, err := h.user(r.Context(), userID)
	if err != nil {
		writeErr(w, err)
		return
	}
	wa, err := h.webAuthn()
	if err != nil {
		writeErr(w, err)
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(req.Credential)
	if err != nil || parsed == nil || !parsed.Response.AuthenticatorData.Flags.HasUserVerified() {
		writeErr(w, errStepUpRequired)
		return
	}
	credential, err := wa.ValidateLogin(user, session, parsed)
	if err != nil || credential == nil || !credential.Flags.UserVerified {
		writeErr(w, errStepUpRequired)
		return
	}
	credentialData, err := json.Marshal(credential)
	if err != nil {
		writeErr(w, err)
		return
	}
	if err = h.Passkeys.Update(r.Context(), store.WebAuthnCredential{CredentialID: credential.ID, CredentialData: credentialData}); err != nil {
		writeErr(w, err)
		return
	}
	grant, err := randomStepUpToken()
	if err != nil {
		writeErr(w, err)
		return
	}
	if _, err = h.DB.ExecContext(r.Context(), `INSERT INTO operator_stepup_grants (token_hash,user_id,access_token_hash,purpose,expires_at) VALUES ($1,$2,$3,$4,now()+interval '20 seconds')`, hashStepUp(grant), userID, accessHash[:], req.Purpose); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]string{"grant": grant})
}

func validStepUpPurpose(s string) bool {
	switch s {
	case "operator_role_change", "operator_remove", "operator_session_revoke", "operator_passkey_remove", "secret_reveal", "secret_mutation":
		return true
	default:
		return false
	}
}

func (h *OperatorHandlers) authorizeStepUpPurpose(w http.ResponseWriter, r *http.Request, purpose string) bool {
	if strings.HasPrefix(purpose, "secret_") {
		return true // adminOnly already authenticated this operator
	}
	if h.Store == nil {
		writeErr(w, errAdminStoresUnavailable)
		return false
	}
	userID := UserIDFromContext(r)
	items, err := h.Store.List(r.Context())
	if err != nil {
		writeErr(w, err)
		return false
	}
	for _, item := range items {
		if item.UserID == userID {
			if item.Role == "owner" {
				return true
			}
			writeErr(w, errNotOwner)
			return false
		}
	}
	writeErr(w, errNotOwner)
	return false
}

func (h *OperatorHandlers) ConsumeStepUp(w http.ResponseWriter, r *http.Request) {
	var req beginStepUpRequest
	if json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req) != nil || (req.Purpose != "secret_reveal" && req.Purpose != "secret_mutation") {
		writeBadRequest(w, "a valid secret step-up purpose is required")
		return
	}
	if err := h.consumeGrant(r, req.Purpose); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]bool{"consumed": true})
}
func randomStepUpToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func hashStepUp(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

func (h *OperatorHandlers) consumeGrant(r *http.Request, purpose string) error {
	if h.DB == nil {
		return errStepUpRequired
	}
	grant := r.Header.Get("X-CSAG-Operator-Grant")
	if len(grant) < 32 {
		return errStepUpRequired
	}
	userID := r.Context().Value(userIDContextKey).(string)
	accessHash := sha256.Sum256([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
	var used string
	err := h.DB.QueryRowContext(r.Context(), `DELETE FROM operator_stepup_grants WHERE token_hash=$1 AND user_id=$2 AND access_token_hash=$3 AND purpose=$4 AND expires_at>now() RETURNING purpose`, hashStepUp(grant), userID, accessHash[:], purpose).Scan(&used)
	if errors.Is(err, sql.ErrNoRows) {
		return errStepUpRequired
	}
	return err
}

func (h *OperatorHandlers) List(w http.ResponseWriter, r *http.Request) {
	if h.Store == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}
	items, err := h.Store.List(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]any{"operators": items, "total": len(items)})
}

func (h *OperatorHandlers) SetRole(w http.ResponseWriter, r *http.Request, userID string) {
	if !looksLikeUUID(userID) {
		writeBadRequest(w, "operator id must be a UUID")
		return
	}
	var req struct {
		Role string `json:"role"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req) != nil || !operator.ValidRole(req.Role) {
		writeBadRequest(w, "role must be owner, admin, or viewer")
		return
	}
	if err := h.consumeGrant(r, "operator_role_change"); err != nil {
		writeErr(w, err)
		return
	}
	mutator, ok := h.Store.(interface {
		SetRole(context.Context, string, string) error
	})
	if !ok {
		writeErr(w, errAdminStoresUnavailable)
		return
	}
	if err := mutator.SetRole(r.Context(), userID, req.Role); err != nil {
		writeErr(w, err)
		return
	}
	if h.Audit != nil {
		_ = h.Audit.Record(r.Context(), store.AuditEvent{Type: store.AuditEventType("operator_role_changed"), UserID: r.Context().Value(userIDContextKey).(string), Metadata: map[string]string{"target_user_id": userID, "role": req.Role}})
	}
	writeData(w, http.StatusOK, map[string]bool{"updated": true})
}

func (h *OperatorHandlers) Remove(w http.ResponseWriter, r *http.Request, userID string) {
	if !looksLikeUUID(userID) {
		writeBadRequest(w, "operator id must be a UUID")
		return
	}
	if err := h.consumeGrant(r, "operator_remove"); err != nil {
		writeErr(w, err)
		return
	}
	mutator, ok := h.Store.(interface {
		Revoke(context.Context, string) error
	})
	if !ok {
		writeErr(w, errAdminStoresUnavailable)
		return
	}
	if err := mutator.Revoke(r.Context(), userID); err != nil {
		writeErr(w, err)
		return
	}
	if h.Sessions != nil {
		if err := h.Sessions.RevokeAllForUser(r.Context(), userID); err != nil {
			writeErr(w, err)
			return
		}
	}
	if h.Audit != nil {
		_ = h.Audit.Record(r.Context(), store.AuditEvent{Type: store.AuditEventType("operator_removed"), UserID: r.Context().Value(userIDContextKey).(string), Metadata: map[string]string{"target_user_id": userID}})
	}
	writeData(w, http.StatusOK, map[string]bool{"removed": true})
}

func (h *OperatorHandlers) requireOperator(w http.ResponseWriter, r *http.Request, userID string) bool {
	if h.Store == nil {
		writeErr(w, errAdminStoresUnavailable)
		return false
	}
	items, err := h.Store.List(r.Context())
	if err != nil {
		writeErr(w, err)
		return false
	}
	for _, item := range items {
		if item.UserID == userID {
			return true
		}
	}
	writeErr(w, operator.ErrNotFound)
	return false
}

type operatorSessionDTO struct {
	ID        string    `json:"id"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	Device    string    `json:"device"`
	CreatedAt time.Time `json:"created_at"`
}

func (h *OperatorHandlers) ListSessions(w http.ResponseWriter, r *http.Request, userID string) {
	if !looksLikeUUID(userID) {
		writeBadRequest(w, "operator id must be a UUID")
		return
	}
	if !h.requireOperator(w, r, userID) {
		return
	}
	if h.Sessions == nil || h.Users == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}
	user, err := h.Users.GetByID(r.Context(), userID)
	if err != nil {
		writeErr(w, err)
		return
	}
	limit, err := queryLimit(r)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	offset, err := queryOffset(r)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	sessions, err := h.Sessions.ListByUser(r.Context(), userID)
	if err != nil {
		writeErr(w, err)
		return
	}
	sort.SliceStable(sessions, func(i, j int) bool { return sessions[i].CreatedAt.After(sessions[j].CreatedAt) })
	total := len(sessions)
	start := min(offset, total)
	end := min(start+limit, total)
	items := make([]operatorSessionDTO, 0, end-start)
	for _, session := range sessions[start:end] {
		items = append(items, operatorSessionDTO{
			ID: session.ID, IP: session.IP, UserAgent: session.UserAgent,
			Device: security.ParseUserAgent(session.UserAgent).String(), CreatedAt: session.CreatedAt.UTC(),
		})
	}
	writeData(w, http.StatusOK, map[string]any{"sessions": items, "total": total, "limit": limit, "offset": offset, "email": user.Email})
}

func (h *OperatorHandlers) RevokeSession(w http.ResponseWriter, r *http.Request, userID, sessionID string) {
	if !looksLikeUUID(userID) {
		writeBadRequest(w, "operator id must be a UUID")
		return
	}
	if !h.requireOperator(w, r, userID) {
		return
	}
	if h.Sessions == nil || h.Engine == nil || h.Audit == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}
	if err := h.consumeGrant(r, "operator_session_revoke"); err != nil {
		writeErr(w, err)
		return
	}
	session, err := h.Sessions.GetByID(r.Context(), sessionID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (session.UserID != userID || session.RevokedAt != nil)) {
		writeErr(w, store.ErrNotFound)
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := cryden.RevokeSession(r.Context(), h.Engine, sessionID, userID); err != nil {
		writeErr(w, err)
		return
	}
	if err := h.Audit.Record(r.Context(), store.AuditEvent{
		Type: store.AuditEventType("admin_operator_session_revoked"), UserID: UserIDFromContext(r), IP: CallerIP(r),
		Metadata: map[string]string{"session_id": sessionID, "target_user_id": userID},
	}); err != nil {
		log.Printf("operator sessions: audit record error: %v", err)
	}
	writeData(w, http.StatusOK, map[string]bool{"revoked": true})
}

func (h *OperatorHandlers) RevokeAllSessions(w http.ResponseWriter, r *http.Request, userID string) {
	if !looksLikeUUID(userID) {
		writeBadRequest(w, "operator id must be a UUID")
		return
	}
	if !h.requireOperator(w, r, userID) {
		return
	}
	if h.Sessions == nil || h.Audit == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}
	if err := h.consumeGrant(r, "operator_session_revoke"); err != nil {
		writeErr(w, err)
		return
	}
	sessions, err := h.Sessions.ListByUser(r.Context(), userID)
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := h.Sessions.RevokeAllForUser(r.Context(), userID); err != nil {
		writeErr(w, err)
		return
	}
	if err := h.Audit.Record(r.Context(), store.AuditEvent{
		Type: store.AuditEventType("admin_operator_sessions_revoked_all"), UserID: UserIDFromContext(r), IP: CallerIP(r),
		Metadata: map[string]string{"target_user_id": userID, "count": strconv.Itoa(len(sessions))},
	}); err != nil {
		log.Printf("operator sessions: audit record error: %v", err)
	}
	writeData(w, http.StatusOK, map[string]int{"revoked": len(sessions)})
}

type operatorPasskeyDTO struct {
	CredentialID string     `json:"credential_id"`
	Nickname     string     `json:"nickname"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
}

func (h *OperatorHandlers) ListPasskeys(w http.ResponseWriter, r *http.Request, userID string) {
	if !looksLikeUUID(userID) {
		writeBadRequest(w, "operator id must be a UUID")
		return
	}
	if !h.requireOperator(w, r, userID) {
		return
	}
	if h.Passkeys == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}
	items, err := h.Passkeys.ListByUser(r.Context(), userID)
	if err != nil {
		writeErr(w, err)
		return
	}
	out := make([]operatorPasskeyDTO, 0, len(items))
	for _, item := range items {
		dto := operatorPasskeyDTO{
			CredentialID: base64.URLEncoding.EncodeToString(item.CredentialID),
			Nickname:     item.Nickname, CreatedAt: item.CreatedAt.UTC(),
		}
		if item.LastUsedAt != nil {
			used := item.LastUsedAt.UTC()
			dto.LastUsedAt = &used
		}
		out = append(out, dto)
	}
	writeData(w, http.StatusOK, map[string]any{"passkeys": out, "total": len(out)})
}

func (h *OperatorHandlers) RemovePasskey(w http.ResponseWriter, r *http.Request, userID, credentialID string) {
	if !looksLikeUUID(userID) {
		writeBadRequest(w, "operator id must be a UUID")
		return
	}
	if !h.requireOperator(w, r, userID) {
		return
	}
	credentialBytes, err := base64.URLEncoding.Strict().DecodeString(credentialID)
	if err != nil || len(credentialBytes) == 0 || base64.URLEncoding.EncodeToString(credentialBytes) != credentialID {
		writeBadRequest(w, "passkey id is invalid")
		return
	}
	if h.DB == nil || h.Passkeys == nil || h.Audit == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}
	if err := h.consumeGrant(r, "operator_passkey_remove"); err != nil {
		writeErr(w, err)
		return
	}
	tx, err := h.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(r.Context(), `LOCK TABLE webauthn_credentials IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		writeErr(w, err)
		return
	}
	var exists bool
	if err := tx.QueryRowContext(r.Context(), `SELECT EXISTS (SELECT 1 FROM webauthn_credentials WHERE user_id=$1 AND credential_id=$2)`, userID, credentialBytes).Scan(&exists); err != nil {
		writeErr(w, err)
		return
	}
	if !exists {
		writeErr(w, store.ErrNotFound)
		return
	}
	var count int
	if err := tx.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM webauthn_credentials WHERE user_id=$1`, userID).Scan(&count); err != nil {
		writeErr(w, err)
		return
	}
	if count <= 1 {
		writeErr(w, errLastOperatorPasskey)
		return
	}
	result, err := tx.ExecContext(r.Context(), `DELETE FROM webauthn_credentials WHERE user_id=$1 AND credential_id=$2`, userID, credentialBytes)
	if err != nil {
		writeErr(w, err)
		return
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		writeErr(w, err)
		return
	}
	if deleted == 0 {
		writeErr(w, store.ErrNotFound)
		return
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, err)
		return
	}
	if err := h.Audit.Record(r.Context(), store.AuditEvent{Type: store.EventWebAuthnRemoved, UserID: userID}); err != nil {
		log.Printf("operator passkeys: removal audit record error: %v", err)
	}
	if err := h.Audit.Record(r.Context(), store.AuditEvent{
		Type: store.AuditEventType("admin_operator_passkey_removed"), UserID: UserIDFromContext(r), IP: CallerIP(r),
		Metadata: map[string]string{"credential_id": credentialID, "target_user_id": userID},
	}); err != nil {
		log.Printf("operator passkeys: admin audit record error: %v", err)
	}
	writeData(w, http.StatusOK, map[string]bool{"removed": true})
}
