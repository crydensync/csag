package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/crydensync/api/askai"
	"github.com/crydensync/api/shiplog"
	crydenai "github.com/crydensync/cryden/v2/ai"
	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/store"
)

const adminAISourceLimit = 50

// These read interfaces deliberately omit Record and Insert. The AI handlers
// can inspect existing data but have no method with which to change it.
type adminAILogReader interface {
	List(context.Context, logger.Level, int) ([]shiplog.Entry, error)
}

type adminAIAuditReader interface {
	SearchByType(context.Context, store.AuditEventType, int) ([]store.AuditEvent, error)
}

type AdminAIHandlers struct {
	Service   *askai.Service
	LogReader adminAILogReader
	Audit     adminAIAuditReader
}

// Query is admin-only. The model may produce only a cryden QueryIntent, which
// is validated against the engine's entity, field, operator and row-limit
// allowlists before the read-only store executes it.
func (h *AdminAIHandlers) Query(w http.ResponseWriter, r *http.Request) {
	if h.Service == nil {
		writeErr(w, errAskAIUnavailable)
		return
	}
	var request struct {
		Question string `json:"question"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeBadRequest(w, "malformed request body")
		return
	}
	result, err := h.Service.AdminQuery(r.Context(), request.Question)
	if errors.Is(err, crydenai.ErrUnsafeQueryIntent) {
		writeBadRequest(w, "the requested query is outside CSAG's read-only data rules")
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, result)
}

// Logs composes a summary from the latest redacted log rows. The source rows
// are bounded, and the citation is attached by the handler rather than by the
// model.
func (h *AdminAIHandlers) Logs(w http.ResponseWriter, r *http.Request) {
	if h.Service == nil {
		writeErr(w, errAskAIUnavailable)
		return
	}
	if h.LogReader == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}
	entries, err := h.LogReader.List(r.Context(), logger.LevelDebug, adminAISourceLimit)
	if err != nil {
		writeErr(w, err)
		return
	}
	rows := make([][]string, 0, len(entries))
	for _, entry := range entries {
		rows = append(rows, []string{
			entry.Level.String(),
			clipAIInput(entry.Message, 500),
			entry.Sink,
			entry.ShippedAt.UTC().Format(time.RFC3339),
		})
	}
	result := crydenai.QueryResult{
		Columns: []string{"level", "message", "sink", "shipped_at"},
		Rows:    rows,
	}
	answer, err := h.Service.ComposeAdminAnswer(r.Context(),
		"Summarize these recent redacted log events. Identify repeated errors or patterns, and say when the rows do not support a conclusion.",
		"shipped_logs", result)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, answer)
}

type anomalyScanRequest struct {
	Since string `json:"since"`
}

// AnomaliesScan summarizes flagged security events from a bounded time
// window. It reads only the two event types the review queue recognizes.
func (h *AdminAIHandlers) AnomaliesScan(w http.ResponseWriter, r *http.Request) {
	if h.Service == nil {
		writeErr(w, errAskAIUnavailable)
		return
	}
	if h.Audit == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}
	var req anomalyScanRequest
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}
	window, err := anomalyScanDuration(req.Since)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	since := time.Now().UTC().Add(-window)
	events := make([]store.AuditEvent, 0, adminAISourceLimit)
	for _, eventType := range anomalyEventTypes {
		found, err := h.Audit.SearchByType(r.Context(), eventType, adminAISourceLimit)
		if err != nil {
			writeErr(w, err)
			return
		}
		for _, event := range found {
			if !event.CreatedAt.Before(since) {
				events = append(events, event)
			}
		}
	}
	sortAnomalies(events)
	if len(events) > adminAISourceLimit {
		events = events[:adminAISourceLimit]
	}
	rows := make([][]string, 0, len(events))
	for _, event := range events {
		rows = append(rows, []string{
			string(event.Type),
			event.Metadata["signals"],
			event.UserID,
			event.IP,
			event.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	result := crydenai.QueryResult{
		Columns: []string{"type", "signals", "user_id", "ip", "created_at"},
		Rows:    rows,
	}
	windowName := req.Since
	answer, err := h.Service.ComposeAdminAnswer(r.Context(),
		fmt.Sprintf("Summarize the flagged authentication events from the last %s. Describe only patterns supported by these rows.", windowName),
		"anomalies", result)
	if err != nil {
		writeErr(w, err)
		return
	}
	answer.Since = windowName
	writeData(w, http.StatusOK, answer)
}

// Audit runs a question only against the audit_events entity and returns the
// structured rows. The entity restriction is enforced in askai.Service after
// parsing and before query execution.
func (h *AdminAIHandlers) AuditQuery(w http.ResponseWriter, r *http.Request) {
	if h.Service == nil {
		writeErr(w, errAskAIUnavailable)
		return
	}
	var request struct {
		Question string `json:"question"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeBadRequest(w, "malformed request body")
		return
	}
	result, err := h.Service.AdminAudit(r.Context(), request.Question)
	if errors.Is(err, crydenai.ErrUnsafeQueryIntent) {
		writeBadRequest(w, "the requested query is outside the audit-only read rules")
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, result)
}

// Ask composes prose from a validated admin query. The citation fields come
// from the query result and are never requested from the model.
func (h *AdminAIHandlers) Ask(w http.ResponseWriter, r *http.Request) {
	if h.Service == nil {
		writeErr(w, errAskAIUnavailable)
		return
	}
	var request struct {
		Question string `json:"question"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeBadRequest(w, "malformed request body")
		return
	}
	result, err := h.Service.AdminAsk(r.Context(), request.Question)
	if errors.Is(err, crydenai.ErrUnsafeQueryIntent) {
		writeBadRequest(w, "the requested query is outside CSAG's read-only data rules")
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, result)
}

func anomalyScanDuration(value string) (time.Duration, error) {
	switch value {
	case "1h":
		return time.Hour, nil
	case "24h":
		return 24 * time.Hour, nil
	case "7d":
		return 7 * 24 * time.Hour, nil
	case "30d":
		return 30 * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("since must be one of: 1h, 24h, 7d, 30d")
	}
}

func clipAIInput(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) <= max {
		return value
	}
	return value[:max]
}
