package httpapi

import (
	"net/http"
	"time"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/store"
)

type EmailHandlers struct {
	Engine *cryden.Engine

	// Audit backs GET /v1/admin/email/stats. The same instance main.go
	// handed cryden, for the reason httpapi.Deps gives: a report read
	// from a second copy of the store would describe events the engine
	// cannot see. Nil in a router built without it (tests), which is a
	// wiring fact answered 404 rather than a server fault.
	Audit store.AuditStore
}

// RequestChange, auth required.
func (h *EmailHandlers) RequestChange(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NewEmail string `json:"new_email"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}

	userID := UserIDFromContext(r)
	if err := cryden.RequestEmailChange(r.Context(), h.Engine, userID, req.NewEmail); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]string{"status": "verification email sent"})
}

// ConfirmChange, deliberately public, no auth middleware. The token
// itself (from the email link) is the proof of authorization, the
// user clicking it may not have an active browser session.
func (h *EmailHandlers) ConfirmChange(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}

	if err := cryden.ConfirmEmailChange(r.Context(), h.Engine, req.Token); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]string{"status": "email changed"})
}

// emailStatsDTO is the whole email report, and every field counts EVENTS.
//
// The prototype's email screen promised delivery health, click-through and
// magic links sent per day. None of that exists to read: cryden sends
// nothing itself, the senders here are console stand-ins that log, and a
// log line is not a delivery record. What the engine does record, system
// wide and forever, are the audit events each email-shaped flow writes at
// the moment it asks a sender to send. That is what this report counts,
// and the field names say so rather than borrowing words ("sent",
// "delivered") that claim a confirmation this API does not have.
type emailStatsDTO struct {
	WindowDays int `json:"window_days"`

	// MagicLinksRequested counts EventMagicLinkRequested, the event
	// RequestMagicLink records after its sender was called. It is the
	// closest thing to "magic links sent" this deployment has, and it
	// includes requests for addresses that hold no account, the engine
	// answers a magic-link request identically whether or not the email
	// belongs to an account, so an attacker probing addresses is counted
	// here too. That is what the engine recorded, not a cleaned-up story.
	MagicLinksRequested         int `json:"magic_links_requested"`
	MagicLinksRequestedInWindow int `json:"magic_links_requested_in_window"`

	// EmailChangesRequested and EmailChanged are the two halves of the
	// email-change flow: the request sends the confirmation message to
	// the NEW address, and the change only lands when its token is
	// confirmed. Requested minus Confirmed is the pair worth reading ,
	// requests that never confirm are either abandoned or mistyped
	// addresses, and the windowed pair says whether that is happening
	// now. (Changed is used rather than Confirmed: the engine's own
	// event type is email_changed, and the console's wording follows the
	// event, not this handler.)
	EmailChangesRequested         int `json:"email_changes_requested"`
	EmailChangesRequestedInWindow int `json:"email_changes_requested_in_window"`
	EmailChangesConfirmed         int `json:"email_changes_confirmed"`
	EmailChangesConfirmedInWindow int `json:"email_changes_confirmed_in_window"`
}

// emailStatsEvents pairs each count with the event type it reads, so the
// loop below and any future reader agree on the mapping. Signup email
// verification is not in this list: this engine has no signup-verification
// flow to count (cryden's PurposeEmailVerify is defined but no shipped
// code path records one), and a row for an event that can never occur
// would be a promise about the engine this repo does not own.
var emailStatsEvents = []struct {
	name    string
	kind    store.AuditEventType
	allTime func(*emailStatsDTO) *int
	window  func(*emailStatsDTO) *int
}{
	{"magic_links_requested", store.EventMagicLinkRequested,
		func(d *emailStatsDTO) *int { return &d.MagicLinksRequested },
		func(d *emailStatsDTO) *int { return &d.MagicLinksRequestedInWindow }},
	{"email_changes_requested", store.EventEmailChangeRequested,
		func(d *emailStatsDTO) *int { return &d.EmailChangesRequested },
		func(d *emailStatsDTO) *int { return &d.EmailChangesRequestedInWindow }},
	{"email_changes_confirmed", store.EventEmailChanged,
		func(d *emailStatsDTO) *int { return &d.EmailChangesConfirmed },
		func(d *emailStatsDTO) *int { return &d.EmailChangesConfirmedInWindow }},
}

// Stats, admin required (see router.go). Reports email-shaped activity as
// the engine's own audit events, all-time and over a window.
//
// Read-only by construction, like the security reports beside it: it calls
// count methods and records nothing. It counts requests, not deliveries ,
// the senders are this repo's console stand-ins writing to a log, so
// nothing here can honestly claim a message reached anyone, and the
// console's screen words it that way rather than promising delivery health
// it cannot read.
func (h *EmailHandlers) Stats(w http.ResponseWriter, r *http.Request) {
	if h.Audit == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}

	windowDays, err := queryInt(r, "window_days", hashMigrationDefaultWindowDays, 1, 365)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}

	ctx := r.Context()

	// A zero time.Time as `since` is an open lower bound rather than a
	// date anyone chose: both store implementations read it as "at or
	// after the beginning of time", so this is the all-time count.
	// CountByType omits a type that did not occur, which is why a missing
	// key reads as zero rather than as an error.
	allTime, err := h.Audit.CountByType(ctx, time.Time{})
	if err != nil {
		writeErr(w, err)
		return
	}
	windowed, err := h.Audit.CountByType(ctx, time.Now().AddDate(0, 0, -windowDays))
	if err != nil {
		writeErr(w, err)
		return
	}

	var dto emailStatsDTO
	dto.WindowDays = windowDays
	for _, e := range emailStatsEvents {
		*e.allTime(&dto) = allTime[e.kind]
		*e.window(&dto) = windowed[e.kind]
	}

	writeData(w, http.StatusOK, dto)
}
