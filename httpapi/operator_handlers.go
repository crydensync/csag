package httpapi

import (
	"context"
	"net/http"

	"github.com/crydensync/api/operator"
)

// OperatorHandlers exposes the API's live operator roster to admins. Mutations
// remain unavailable until the API can enforce the console's required WebAuthn
// step-up for role changes and removals.
type OperatorHandlers struct {
	Store interface {
		List(context.Context) ([]operator.Operator, error)
	}
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
