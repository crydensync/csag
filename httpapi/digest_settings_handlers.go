package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/crydensync/api/digest"
)

type DigestSettingsHandlers struct {
	Runtime *digest.Runtime
	Sender  digest.DeliverySender
}

type digestScheduleDTO struct {
	digest.ScheduleSettings
	DeliveryAvailable bool `json:"delivery_available"`
}

func (h *DigestSettingsHandlers) Read(w http.ResponseWriter, r *http.Request) {
	if h.Runtime == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}
	writeData(w, http.StatusOK, digestScheduleDTO{
		ScheduleSettings:  h.Runtime.Snapshot(),
		DeliveryAvailable: h.Sender != nil,
	})
}

func (h *DigestSettingsHandlers) Save(w http.ResponseWriter, r *http.Request) {
	if h.Runtime == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var next digest.ScheduleSettings
	if err := decoder.Decode(&next); err != nil {
		writeBadRequest(w, "malformed digest settings")
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		writeBadRequest(w, "malformed digest settings")
		return
	}
	next.DayOfWeek = strings.ToLower(next.DayOfWeek)
	if err := next.Validate(); err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	if next.DeliveryEnabled && h.Sender == nil {
		writeErr(w, digest.ErrDeliveryUnavailable)
		return
	}
	if err := h.Runtime.Save(r.Context(), next); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, digestScheduleDTO{
		ScheduleSettings:  h.Runtime.Snapshot(),
		DeliveryAvailable: h.Sender != nil,
	})
}
