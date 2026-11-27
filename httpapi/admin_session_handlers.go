package httpapi

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
)

// AdminSessionHandlers serves the console's system-wide active-session view.
// The response deliberately contains no refresh-token material.
type AdminSessionHandlers struct {
	DB     *sql.DB
	Engine *cryden.Engine
	Audit  store.AuditStore
}

type adminSessionDTO struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	Device    string    `json:"device"`
	CreatedAt time.Time `json:"created_at"`
}

func (h *AdminSessionHandlers) List(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
		writeErr(w, errAdminStoresUnavailable)
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

	var total int
	if err := h.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL`).Scan(&total); err != nil {
		writeErr(w, err)
		return
	}
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT s.id, s.user_id, u.email, s.ip, s.user_agent, s.created_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.revoked_at IS NULL
		ORDER BY s.created_at DESC, s.id DESC
		LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()
	items := make([]adminSessionDTO, 0, limit)
	for rows.Next() {
		var item adminSessionDTO
		var ip, userAgent sql.NullString
		if err := rows.Scan(&item.ID, &item.UserID, &item.Email, &ip, &userAgent, &item.CreatedAt); err != nil {
			writeErr(w, err)
			return
		}
		item.IP, item.UserAgent = ip.String, userAgent.String
		item.Device = security.ParseUserAgent(item.UserAgent).String()
		item.CreatedAt = item.CreatedAt.UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]any{
		"sessions": items, "total": total, "limit": limit, "offset": offset,
	})
}

func (h *AdminSessionHandlers) Revoke(w http.ResponseWriter, r *http.Request, sessionID string) {
	if h.DB == nil || h.Engine == nil || h.Audit == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}
	var userID string
	err := h.DB.QueryRowContext(r.Context(), `SELECT user_id FROM sessions WHERE id = $1 AND revoked_at IS NULL`, sessionID).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
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
	operatorID := UserIDFromContext(r)
	if err := h.Audit.Record(r.Context(), store.AuditEvent{
		Type: store.AuditEventType("admin_session_revoked"), UserID: operatorID, IP: CallerIP(r),
		Metadata: map[string]string{"session_id": sessionID, "target_user_id": userID},
	}); err != nil {
		log.Printf("admin sessions: audit record error: %v", err)
	}
	writeData(w, http.StatusOK, map[string]string{"status": "session revoked"})
}

func (h *AdminSessionHandlers) RevokeAll(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil || h.Audit == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}
	result, err := h.DB.ExecContext(r.Context(), `UPDATE sessions SET revoked_at = now() WHERE revoked_at IS NULL`)
	if err != nil {
		writeErr(w, err)
		return
	}
	count, err := result.RowsAffected()
	if err != nil {
		writeErr(w, err)
		return
	}
	operatorID := UserIDFromContext(r)
	if err := h.Audit.Record(r.Context(), store.AuditEvent{
		Type: store.AuditEventType("admin_sessions_revoked_all"), UserID: operatorID, IP: CallerIP(r),
		Metadata: map[string]string{"count": strconv.FormatInt(count, 10)},
	}); err != nil {
		log.Printf("admin sessions: audit record error: %v", err)
	}
	writeData(w, http.StatusOK, map[string]any{"status": "sessions revoked", "revoked": count})
}
