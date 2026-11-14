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
	"net/http"
	"strings"

	"github.com/crydensync/api/config"
	"github.com/crydensync/api/operator"
	"github.com/crydensync/cryden/v2/store"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var errStepUpRequired = errors.New("fresh WebAuthn step-up required")

type OperatorHandlers struct {
	Store interface {
		List(context.Context) ([]operator.Operator, error)
	}
	DB       *sql.DB
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

func validStepUpPurpose(s string) bool { return s == "operator_role_change" || s == "operator_remove" }
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
