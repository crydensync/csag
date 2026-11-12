package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/crydensync/api/shiplog"
)

type LoggingSettingsHandlers struct {
	Runtime    *shiplog.Runtime
	Redaction  string
	HashKeySet bool
}

type loggingSettingsDTO struct {
	Enabled    bool   `json:"enabled"`
	MinLevel   string `json:"min_level"`
	Redaction  string `json:"redaction"`
	HashKeySet bool   `json:"hash_key_set"`
}

func (h *LoggingSettingsHandlers) available(w http.ResponseWriter) bool {
	if h.Runtime == nil {
		writeErr(w, errAdminStoresUnavailable)
		return false
	}
	return true
}

func (h *LoggingSettingsHandlers) Read(w http.ResponseWriter, r *http.Request) {
	if !h.available(w) {
		return
	}
	active := h.Runtime.Snapshot()
	writeData(w, http.StatusOK, loggingSettingsDTO{
		Enabled: active.Enabled, MinLevel: active.MinLevel,
		Redaction: h.Redaction, HashKeySet: h.HashKeySet,
	})
}

func (h *LoggingSettingsHandlers) Save(w http.ResponseWriter, r *http.Request) {
	if !h.available(w) {
		return
	}
	var request struct {
		Enabled  *bool  `json:"enabled"`
		MinLevel string `json:"min_level"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Enabled == nil {
		writeBadRequest(w, "enabled and min_level are required")
		return
	}
	next := shiplog.RuntimeSettings{Enabled: *request.Enabled, MinLevel: request.MinLevel}
	if err := next.Validate(); err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	if err := h.Runtime.Save(r.Context(), next); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, loggingSettingsDTO{
		Enabled: next.Enabled, MinLevel: next.MinLevel,
		Redaction: h.Redaction, HashKeySet: h.HashKeySet,
	})
}
