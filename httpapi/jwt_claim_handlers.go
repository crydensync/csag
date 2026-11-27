package httpapi

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/crydensync/api/jwtclaims"
	"github.com/crydensync/api/usermeta"
)

type JWTClaimHandlers struct{ Provider *jwtclaims.Provider }

var claimPreviewUserID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type jwtClaimsRequest struct {
	Mappings []jwtclaims.Mapping `json:"mappings"`
}

func (h *JWTClaimHandlers) ready(w http.ResponseWriter) bool {
	if h.Provider == nil || h.Provider.Store == nil {
		writeErr(w, errSettingsNotConfigured)
		return false
	}
	return true
}

func (h *JWTClaimHandlers) Read(w http.ResponseWriter, r *http.Request) {
	if !h.ready(w) {
		return
	}
	config, err := h.Provider.Read(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]any{"mappings": config.Mappings, "reserved_claim_names": usermeta.ReservedKeys()})
}

func (h *JWTClaimHandlers) Save(w http.ResponseWriter, r *http.Request) {
	if !h.ready(w) {
		return
	}
	var request jwtClaimsRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeBadRequest(w, "malformed request body")
		return
	}
	config := jwtclaims.Config{Mappings: request.Mappings}
	if config.Mappings == nil {
		config.Mappings = []jwtclaims.Mapping{}
	}
	if err := config.Validate(); err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	if err := h.Provider.Save(r.Context(), config); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]any{"mappings": config.Mappings, "reserved_claim_names": usermeta.ReservedKeys()})
}

func (h *JWTClaimHandlers) Preview(w http.ResponseWriter, r *http.Request) {
	if !h.ready(w) {
		return
	}
	var request struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil || strings.TrimSpace(request.UserID) == "" {
		writeBadRequest(w, "user_id is required")
		return
	}
	if !claimPreviewUserID.MatchString(request.UserID) {
		writeBadRequest(w, "user_id must be a UUID")
		return
	}
	if h.Provider.Users == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}
	user, err := h.Provider.Users.GetByID(r.Context(), request.UserID)
	if err != nil {
		writeErr(w, err)
		return
	}
	claims, err := h.Provider.AccessTokenClaims(r.Context(), user.ID)
	if err != nil {
		writeErr(w, err)
		return
	}
	if claims == nil {
		claims = map[string]any{}
	}
	writeData(w, http.StatusOK, map[string]any{
		"user_id": user.ID, "email": user.Email, "claims": claims,
		"signed": false,
	})
}
