package httpapi

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// AdminAuditHandlers exposes the engine's audit history with bounded,
// keyset pagination. It returns only the audit row's public fields.
type AdminAuditHandlers struct{ DB *sql.DB }

type adminAuditCursor struct {
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
}

type adminAuditEventDTO struct {
	ID        string            `json:"id"`
	Type      string            `json:"type"`
	UserID    string            `json:"user_id,omitempty"`
	Email     string            `json:"email,omitempty"`
	IP        string            `json:"ip,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

func (h *AdminAuditHandlers) List(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}
	limit, err := queryInt(r, "limit", 50, 1, 100)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	q := r.URL.Query()
	eventType := queryString(r, "event_type")
	if len(eventType) > 100 {
		writeBadRequest(w, "event_type must be at most 100 characters")
		return
	}
	userID := queryString(r, "user_id")
	if userID != "" && !looksLikeUUID(userID) {
		writeBadRequest(w, "user_id must be a UUID")
		return
	}
	since, err := parseAuditTime(queryString(r, "since"), "since")
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	until, err := parseAuditTime(queryString(r, "until"), "until")
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	if since != nil && until != nil && since.After(*until) {
		writeBadRequest(w, "since must be before or equal to until")
		return
	}
	cursor, err := decodeAuditCursor(q.Get("cursor"))
	if err != nil {
		writeBadRequest(w, "cursor is invalid")
		return
	}

	where := make([]string, 0, 5)
	args := make([]any, 0, 8)
	add := func(condition string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(condition, len(args)))
	}
	if eventType != "" {
		add("e.type = $%d", eventType)
	}
	if userID != "" {
		add("e.user_id = $%d", userID)
	}
	if since != nil {
		add("e.created_at >= $%d", *since)
	}
	if until != nil {
		add("e.created_at <= $%d", *until)
	}
	if cursor != nil {
		args = append(args, cursor.CreatedAt, cursor.ID)
		where = append(where, fmt.Sprintf("(e.created_at, e.id) < ($%d, $%d)", len(args)-1, len(args)))
	}
	query := `SELECT e.id::text, e.type, e.user_id::text, u.email, e.ip, e.metadata, e.created_at
		FROM audit_events e LEFT JOIN users u ON u.id = e.user_id`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	args = append(args, limit+1)
	query += fmt.Sprintf(" ORDER BY e.created_at DESC, e.id DESC LIMIT $%d", len(args))

	rows, err := h.DB.QueryContext(r.Context(), query, args...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()
	items := make([]adminAuditEventDTO, 0, limit+1)
	for rows.Next() {
		var item adminAuditEventDTO
		var userIDValue, email, ip sql.NullString
		var metadata []byte
		if err := rows.Scan(&item.ID, &item.Type, &userIDValue, &email, &ip, &metadata, &item.CreatedAt); err != nil {
			writeErr(w, err)
			return
		}
		item.UserID, item.Email, item.IP = userIDValue.String, email.String, ip.String
		if len(metadata) > 0 && string(metadata) != "null" {
			if err := json.Unmarshal(metadata, &item.Metadata); err != nil {
				writeErr(w, err)
				return
			}
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		writeErr(w, err)
		return
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	var next string
	if hasMore && len(items) > 0 {
		last := items[len(items)-1]
		next, err = encodeAuditCursor(adminAuditCursor{CreatedAt: last.CreatedAt, ID: last.ID})
		if err != nil {
			writeErr(w, err)
			return
		}
	}
	writeData(w, http.StatusOK, map[string]any{
		"events": items, "limit": limit, "has_more": hasMore, "next_cursor": next,
	})
}

func parseAuditTime(raw, field string) (*time.Time, error) {
	if raw == "" {
		return nil, nil
	}
	value, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, fmt.Errorf("%s must be an RFC3339 timestamp", field)
	}
	return &value, nil
}

func encodeAuditCursor(cursor adminAuditCursor) (string, error) {
	data, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func decodeAuditCursor(raw string) (*adminAuditCursor, error) {
	if raw == "" {
		return nil, nil
	}
	if len(raw) > 1024 {
		return nil, fmt.Errorf("cursor too long")
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	var cursor adminAuditCursor
	if err := json.Unmarshal(data, &cursor); err != nil || cursor.ID == "" || !looksLikeUUID(cursor.ID) || cursor.CreatedAt.IsZero() {
		return nil, fmt.Errorf("invalid cursor")
	}
	return &cursor, nil
}
