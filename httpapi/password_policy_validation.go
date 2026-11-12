package httpapi

import (
	"net/http"

	"github.com/crydensync/cryden/v2/auth"

	"github.com/crydensync/api/passwordpolicy"
)

// enforcePasswordPolicy applies the live host policy before calling the
// engine, whose immutable default remains as a second, minimum baseline.
func enforcePasswordPolicy(w http.ResponseWriter, r *http.Request, policy *passwordpolicy.Manager, password string) bool {
	if policy == nil {
		return true
	}
	violations, err := policy.Violations(r.Context(), password)
	if err != nil {
		writeErr(w, err)
		return false
	}
	if len(violations) > 0 {
		writeErr(w, &auth.ErrPasswordPolicyViolation{Violations: violations})
		return false
	}
	return true
}
