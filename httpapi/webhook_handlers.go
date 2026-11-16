package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/crydensync/api/settings"
	"github.com/crydensync/api/webhook"
	"github.com/crydensync/cryden/v2/store"
)

// WebhookHandlers answers the admin webhook delivery log.
//
// Read-only, like the two reports beside it on the admin surface: it lists
// what the delivery worker has done and can take no action. Deliberately no
// "retry this delivery" endpoint here — that would be a write on a surface
// whose neighbouring feature is the AI-assisted tooling CLAUDE.md keeps
// read-only, and re-queuing a delivery is a decision an operator should make
// in the database with the evidence in front of them rather than through a
// button whose consequences are a third party's.
type WebhookHandlers struct {
	// Store is this repo's own delivery log (see the webhook package). Nil
	// when WEBHOOK_URL is unset, which is a wiring fact rather than a
	// server fault — cryden's own "not configured" convention, answered as
	// a 404.
	Store   webhook.Store
	Secrets *settings.Secrets
	Wake    chan<- struct{}
}

type webhookEndpointDTO struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	URL       string `json:"url"`
	Secret    string `json:"secret,omitempty"`
	SecretSet bool   `json:"secret_set"`
}

type webhookEndpointListDTO struct {
	Endpoints []webhookEndpointDTO `json:"endpoints"`
}

func endpointKey(id string) string {
	return settings.WebhookEndpointKey(id)
}

func validEndpointID(id string) bool {
	if id == "default" {
		return true
	}
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func (h *WebhookHandlers) runtimeEndpoints(r *http.Request) ([]webhookEndpointDTO, map[string]settings.WebhookEndpointConfig, error) {
	keys, err := h.Secrets.Keys(r.Context())
	if err != nil {
		return nil, nil, err
	}
	configs := make(map[string]settings.WebhookEndpointConfig)
	for _, key := range keys {
		id := ""
		if key == settings.KeyWebhookEndpoint {
			id = "default"
		} else if strings.HasPrefix(key, settings.KeyWebhookEndpointPrefix) {
			id = strings.TrimPrefix(key, settings.KeyWebhookEndpointPrefix)
		}
		if id == "" || !validEndpointID(id) {
			continue
		}
		raw, getErr := h.Secrets.Get(r.Context(), key)
		if getErr != nil {
			return nil, nil, getErr
		}
		config, decodeErr := settings.UnmarshalWebhookEndpoint(raw)
		if decodeErr != nil {
			return nil, nil, decodeErr
		}
		if config.Name == "" {
			config.Name = "Default"
		}
		configs[id] = config
	}
	ids := make([]string, 0, len(configs))
	for id := range configs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	dtos := make([]webhookEndpointDTO, 0, len(ids))
	for _, id := range ids {
		c := configs[id]
		dtos = append(dtos, webhookEndpointDTO{ID: id, Name: c.Name, URL: c.URL, SecretSet: c.Secret != ""})
	}
	return dtos, configs, nil
}

// Endpoints lists configured runtime destinations without returning secrets.
func (h *WebhookHandlers) Endpoints(w http.ResponseWriter, r *http.Request) {
	if h.Secrets == nil || !h.Secrets.Configured() {
		writeErr(w, errSettingsNotConfigured)
		return
	}
	items, _, err := h.runtimeEndpoints(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, webhookEndpointListDTO{Endpoints: items})
}

// CreateEndpoint creates an independently encrypted destination.
func (h *WebhookHandlers) CreateEndpoint(w http.ResponseWriter, r *http.Request) {
	if h.Secrets == nil || !h.Secrets.Configured() {
		writeErr(w, errSettingsNotConfigured)
		return
	}
	var dto webhookEndpointDTO
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		writeBadRequest(w, "malformed request body")
		return
	}
	dto.Name = strings.TrimSpace(dto.Name)
	config := settings.WebhookEndpointConfig{Name: dto.Name, URL: strings.TrimSpace(dto.URL), Secret: dto.Secret}
	if dto.Name == "" || len(dto.Name) > 80 {
		writeBadRequest(w, "name must contain 1 to 80 characters")
		return
	}
	if err := config.Validate(); err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	var idBytes [16]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		writeErr(w, err)
		return
	}
	id := hex.EncodeToString(idBytes[:])
	raw, err := json.Marshal(config)
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := h.Secrets.Put(r.Context(), endpointKey(id), raw); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusCreated, webhookEndpointDTO{ID: id, Name: config.Name, URL: config.URL, SecretSet: true})
}

// UpdateEndpoint changes a destination; an omitted secret preserves it.
func (h *WebhookHandlers) UpdateEndpoint(w http.ResponseWriter, r *http.Request) {
	if h.Secrets == nil || !h.Secrets.Configured() {
		writeErr(w, errSettingsNotConfigured)
		return
	}
	id := r.PathValue("endpointID")
	if !validEndpointID(id) {
		writeErr(w, store.ErrNotFound)
		return
	}
	var dto webhookEndpointDTO
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		writeBadRequest(w, "malformed request body")
		return
	}
	raw, err := h.Secrets.Get(r.Context(), endpointKey(id))
	if err != nil {
		writeErr(w, err)
		return
	}
	current, err := settings.UnmarshalWebhookEndpoint(raw)
	if err != nil {
		writeErr(w, err)
		return
	}
	if dto.Secret == "" {
		dto.Secret = current.Secret
	}
	if strings.TrimSpace(dto.Name) == "" {
		dto.Name = current.Name
	}
	config := settings.WebhookEndpointConfig{Name: strings.TrimSpace(dto.Name), URL: strings.TrimSpace(dto.URL), Secret: dto.Secret}
	if config.Name == "" || len(config.Name) > 80 {
		writeBadRequest(w, "name must contain 1 to 80 characters")
		return
	}
	if err := config.Validate(); err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	raw, err = json.Marshal(config)
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := h.Secrets.Put(r.Context(), endpointKey(id), raw); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, webhookEndpointDTO{ID: id, Name: config.Name, URL: config.URL, SecretSet: true})
}

// RemoveEndpoint deletes one runtime target without changing other targets.
func (h *WebhookHandlers) RemoveEndpoint(w http.ResponseWriter, r *http.Request) {
	if h.Secrets == nil || !h.Secrets.Configured() {
		writeErr(w, errSettingsNotConfigured)
		return
	}
	id := r.PathValue("endpointID")
	if !validEndpointID(id) {
		writeErr(w, store.ErrNotFound)
		return
	}
	if h.Store != nil {
		pending, err := h.Store.HasUnresolvedDestination(r.Context(), id)
		if err != nil {
			writeErr(w, err)
			return
		}
		if pending {
			writeConflict(w, "webhook_deliveries_pending", "Wait for queued deliveries to finish before removing this destination.")
			return
		}
	}
	if err := h.Secrets.Delete(r.Context(), endpointKey(id)); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]any{"removed": true, "id": id})
}

// Endpoint reports the configured URL and whether a signing secret is stored.
// The secret itself is never returned.
func (h *WebhookHandlers) Endpoint(w http.ResponseWriter, r *http.Request) {
	if h.Secrets == nil || !h.Secrets.Configured() {
		writeErr(w, errSettingsNotConfigured)
		return
	}
	raw, err := h.Secrets.Get(r.Context(), settings.KeyWebhookEndpoint)
	if errors.Is(err, settings.ErrNotFound) {
		writeData(w, http.StatusOK, webhookEndpointDTO{})
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	config, err := settings.UnmarshalWebhookEndpoint(raw)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, webhookEndpointDTO{URL: config.URL, SecretSet: config.Secret != ""})
}

// PutEndpoint saves a runtime webhook destination. Omitting secret preserves
// the existing signing key, since the API never sends it back to the browser.
func (h *WebhookHandlers) PutEndpoint(w http.ResponseWriter, r *http.Request) {
	if h.Secrets == nil || !h.Secrets.Configured() {
		writeErr(w, errSettingsNotConfigured)
		return
	}
	var dto webhookEndpointDTO
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		writeBadRequest(w, "malformed request body")
		return
	}
	if dto.Secret == "" {
		if existing, err := h.Secrets.Get(r.Context(), settings.KeyWebhookEndpoint); err == nil {
			current, decodeErr := settings.UnmarshalWebhookEndpoint(existing)
			if decodeErr != nil {
				writeErr(w, decodeErr)
				return
			}
			dto.Secret = current.Secret
		}
	}
	config := settings.WebhookEndpointConfig{URL: strings.TrimSpace(dto.URL), Secret: dto.Secret}
	if err := config.Validate(); err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	raw, err := json.Marshal(config)
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := h.Secrets.Put(r.Context(), settings.KeyWebhookEndpoint, raw); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, webhookEndpointDTO{URL: config.URL, SecretSet: true})
}

// DeleteEndpoint clears runtime configuration and allows the environment
// configured destination, if present, to take over again.
func (h *WebhookHandlers) DeleteEndpoint(w http.ResponseWriter, r *http.Request) {
	if h.Secrets == nil || !h.Secrets.Configured() {
		writeErr(w, errSettingsNotConfigured)
		return
	}
	if err := h.Secrets.Delete(r.Context(), settings.KeyWebhookEndpoint); err != nil && !errors.Is(err, settings.ErrNotFound) {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, webhookEndpointDTO{})
}

// TestEndpoint queues a representative test event for the configured runtime
// destination. Like production events, delivery happens in the worker.
func (h *WebhookHandlers) TestEndpoint(w http.ResponseWriter, r *http.Request) {
	if h.Store == nil || h.Secrets == nil || !h.Secrets.Configured() {
		writeErr(w, errAdminStoresUnavailable)
		return
	}
	raw, err := h.Secrets.Get(r.Context(), settings.KeyWebhookEndpoint)
	if err != nil {
		writeErr(w, err)
		return
	}
	endpoint, err := settings.UnmarshalWebhookEndpoint(raw)
	if err != nil {
		writeErr(w, err)
		return
	}
	var idBytes [16]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		writeErr(w, err)
		return
	}
	id := hex.EncodeToString(idBytes[:])
	now := time.Now().UTC()
	body, err := json.Marshal(map[string]any{
		"id": id, "type": "webhook.test", "occurred_at": now,
		"metadata": map[string]string{"message": "CSAG webhook test delivery"},
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := h.Store.Enqueue(r.Context(), webhook.Delivery{EventID: id, EventType: "webhook.test", Payload: body}); err != nil {
		writeErr(w, err)
		return
	}
	select {
	case h.Wake <- struct{}{}:
	default:
	}
	writeData(w, http.StatusAccepted, map[string]any{"queued": true, "event_id": id, "endpoint_url": endpoint.URL})
}

// TestDestination queues a representative event for exactly one configured
// target. The destination ID is stored on the row before the worker sees it.
func (h *WebhookHandlers) TestDestination(w http.ResponseWriter, r *http.Request) {
	if h.Store == nil || h.Secrets == nil || !h.Secrets.Configured() {
		writeErr(w, errAdminStoresUnavailable)
		return
	}
	id := r.PathValue("endpointID")
	if !validEndpointID(id) {
		writeErr(w, store.ErrNotFound)
		return
	}
	_, configs, err := h.runtimeEndpoints(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	config, ok := configs[id]
	if !ok {
		writeErr(w, store.ErrNotFound)
		return
	}
	queueTestDelivery(w, r, h.Store, h.Wake, id, config.Name)
}

func queueTestDelivery(w http.ResponseWriter, r *http.Request, queue webhook.Store, wake chan<- struct{}, destinationID, destinationName string) {
	var idBytes [16]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		writeErr(w, err)
		return
	}
	id := hex.EncodeToString(idBytes[:])
	now := time.Now().UTC()
	body, err := json.Marshal(map[string]any{"id": id, "type": "webhook.test", "occurred_at": now, "metadata": map[string]string{"message": "CSAG webhook test delivery"}})
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := queue.Enqueue(r.Context(), webhook.Delivery{EventID: id, EventType: "webhook.test", DestinationID: destinationID, DestinationName: destinationName, Payload: body}); err != nil {
		writeErr(w, err)
		return
	}
	select {
	case wake <- struct{}{}:
	default:
	}
	writeData(w, http.StatusAccepted, map[string]any{"queued": true, "event_id": id, "destination_id": destinationID})
}

// deliveryDTO is one row of the log. It carries the payload as raw JSON
// rather than re-encoding it, so what a console shows is the body that was
// actually POSTed — including key order, which is what a receiver's
// signature is computed over.
type deliveryDTO struct {
	ID              int64  `json:"id"`
	EventID         string `json:"event_id"`
	EventType       string `json:"event_type"`
	DestinationID   string `json:"destination_id"`
	DestinationName string `json:"destination_name"`
	UserID          string `json:"user_id,omitempty"`
	IP              string `json:"ip,omitempty"`

	Payload json.RawMessage `json:"payload"`

	Status webhook.Status `json:"status"`

	// Attempts counts attempts STARTED, which is why it is worth reporting
	// rather than hiding: a delivery at 3 of 5 tells an operator the
	// endpoint has been failing, and a row that failed outright says how
	// many tries it got.
	Attempts int `json:"attempts"`

	// ResponseCode is absent when no response arrived at all — a connection
	// failure or a timeout, which is a different problem from a receiver
	// answering 500, and one an operator fixes in a different place.
	ResponseCode int `json:"response_code,omitempty"`

	// Error is the receiver's own words where it gave any, so a failing
	// delivery can be diagnosed from this response alone.
	Error string `json:"error,omitempty"`

	DurationMS int `json:"duration_ms"`

	CreatedAt     time.Time  `json:"created_at"`
	NextAttemptAt time.Time  `json:"next_attempt_at"`
	DeliveredAt   *time.Time `json:"delivered_at,omitempty"`
}

// deliveriesDTO is the whole response. Statuses is included so a console can
// offer the filter without hardcoding the four values, and Status echoes the
// filter in force — an operator looking at a short list needs to know
// whether it is short because of the filter or because of the traffic.
type deliveriesDTO struct {
	Deliveries []deliveryDTO    `json:"deliveries"`
	Count      int              `json:"count"`
	Status     webhook.Status   `json:"status,omitempty"`
	Statuses   []webhook.Status `json:"statuses"`
}

// Deliveries — admin required (see router.go). Lists the delivery log
// newest first, optionally filtered by status.
func (h *WebhookHandlers) Deliveries(w http.ResponseWriter, r *http.Request) {
	if h.Store == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}

	limit, err := queryLimit(r)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}

	var status webhook.Status
	if raw := queryString(r, "status"); raw != "" {
		var err error
		status, err = webhook.ParseStatus(raw)
		if err != nil {
			// Reported as a 400 naming the four valid values rather than as
			// an unmapped error: an empty list would look like "no
			// deliveries", which is the one thing a filter must never be
			// able to be confused with.
			writeBadRequest(w, fmt.Sprintf("status must be one of: %s", strings.Join(statusNames(), ", ")))
			return
		}
	}

	destinationID := queryString(r, "destination_id")
	if destinationID != "" && !validEndpointID(destinationID) {
		writeBadRequest(w, "destination_id must identify a configured endpoint")
		return
	}
	rows, err := h.Store.ListDestination(r.Context(), status, destinationID, limit)
	if err != nil {
		writeErr(w, err)
		return
	}

	out := make([]deliveryDTO, 0, len(rows))
	for _, d := range rows {
		out = append(out, deliveryDTO{
			ID:              d.ID,
			EventID:         d.EventID,
			EventType:       d.EventType,
			DestinationID:   d.DestinationID,
			DestinationName: d.DestinationName,
			UserID:          d.UserID,
			IP:              d.IP,
			Payload:         d.Payload,
			Status:          d.Status,
			Attempts:        d.Attempts,
			ResponseCode:    d.ResponseCode,
			Error:           d.Error,
			DurationMS:      d.DurationMS,
			CreatedAt:       d.CreatedAt,
			NextAttemptAt:   d.NextAttemptAt,
			DeliveredAt:     d.DeliveredAt,
		})
	}

	writeData(w, http.StatusOK, deliveriesDTO{
		Deliveries: out,
		Count:      len(out),
		Status:     status,
		Statuses:   webhook.Statuses(),
	})
}

func statusNames() []string {
	statuses := webhook.Statuses()
	out := make([]string, 0, len(statuses))
	for _, s := range statuses {
		out = append(out, string(s))
	}
	return out
}
