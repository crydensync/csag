package httpapi

import (
	"log"
	"net/http"
	"strconv"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"

	"github.com/crydensync/api/passwordpolicy"
)

// PasswordPolicyHandlers serves the active, persistent policy used by this
// CSAG instance. Writes are admin-only and audited.
type PasswordPolicyHandlers struct {
	Policy *passwordpolicy.Manager
	Audit  store.AuditStore
}

type passwordPolicyDTO struct {
	MinLength        int  `json:"min_length"`
	MaxLength        int  `json:"max_length"`
	RequireUppercase bool `json:"require_uppercase"`
	RequireLowercase bool `json:"require_lowercase"`
	RequireDigit     bool `json:"require_digit"`
	RequireSymbol    bool `json:"require_symbol"`
}

func policyDTO(policy security.PasswordPolicy) passwordPolicyDTO {
	return passwordPolicyDTO{
		MinLength: policy.MinLength, MaxLength: policy.MaxLength,
		RequireUppercase: policy.RequireUppercase, RequireLowercase: policy.RequireLowercase,
		RequireDigit: policy.RequireDigit, RequireSymbol: policy.RequireSymbol,
	}
}

func (h *PasswordPolicyHandlers) Get(w http.ResponseWriter, r *http.Request) {
	if h.Policy == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}
	policy, err := h.Policy.Current(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, policyDTO(policy))
}

func (h *PasswordPolicyHandlers) Put(w http.ResponseWriter, r *http.Request) {
	if h.Policy == nil || h.Audit == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}
	var req struct {
		MinLength        *int  `json:"min_length"`
		MaxLength        *int  `json:"max_length"`
		RequireUppercase *bool `json:"require_uppercase"`
		RequireLowercase *bool `json:"require_lowercase"`
		RequireDigit     *bool `json:"require_digit"`
		RequireSymbol    *bool `json:"require_symbol"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}
	if req.MinLength == nil || req.MaxLength == nil || req.RequireUppercase == nil ||
		req.RequireLowercase == nil || req.RequireDigit == nil || req.RequireSymbol == nil {
		writeBadRequest(w, "all password policy fields are required")
		return
	}

	next := security.PasswordPolicy{
		MinLength: *req.MinLength, MaxLength: *req.MaxLength,
		RequireUppercase: *req.RequireUppercase, RequireLowercase: *req.RequireLowercase,
		RequireDigit: *req.RequireDigit, RequireSymbol: *req.RequireSymbol,
	}
	if err := passwordpolicy.Validate(next); err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	previous, err := h.Policy.Current(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := h.Policy.Update(r.Context(), next); err != nil {
		writeErr(w, err)
		return
	}

	operatorID := UserIDFromContext(r)
	metadata := map[string]string{
		"by":                  operatorID,
		"min_length":          strconv.Itoa(next.MinLength),
		"max_length":          strconv.Itoa(next.MaxLength),
		"require_uppercase":   strconv.FormatBool(next.RequireUppercase),
		"require_lowercase":   strconv.FormatBool(next.RequireLowercase),
		"require_digit":       strconv.FormatBool(next.RequireDigit),
		"require_symbol":      strconv.FormatBool(next.RequireSymbol),
		"previous_min_length": strconv.Itoa(previous.MinLength),
		"previous_max_length": strconv.Itoa(previous.MaxLength),
	}
	if err := h.Audit.Record(r.Context(), store.AuditEvent{
		Type:   store.AuditEventType("password_policy_changed"),
		UserID: operatorID, IP: CallerIP(r), Metadata: metadata,
	}); err != nil {
		log.Printf("password policy: audit record error: %v", err)
	}
	writeData(w, http.StatusOK, policyDTO(next))
}
