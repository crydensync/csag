package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/crydensync/api/askai"
	crydenai "github.com/crydensync/cryden/v2/ai"
)

type AdminAIHandlers struct{ Service *askai.Service }

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
