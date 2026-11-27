// Package passwordpolicy owns CSAG's active password policy. CSAX Auth
// captures policy when the engine is constructed, so every API password-write
// path validates against this persistent policy before calling the engine.
// The engine's built-in policy remains the minimum baseline; updates may
// strengthen it, never weaken it.
package passwordpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/crydensync/cryden/v2/security"

	"github.com/crydensync/api/settings"
)

type Manager struct {
	mu      sync.RWMutex
	current security.PasswordPolicy
	store   settings.Store
}

// NewManager reads a persisted policy when one exists; otherwise it uses the
// host's initial config. Invalid stored data fails startup rather than being
// silently replaced with a default.
func NewManager(ctx context.Context, store settings.Store, initial security.PasswordPolicy) (*Manager, error) {
	if initial == (security.PasswordPolicy{}) {
		initial = security.DefaultPasswordPolicy
	}
	if err := Validate(initial); err != nil {
		return nil, fmt.Errorf("invalid initial password policy: %w", err)
	}

	m := &Manager{current: initial, store: store}
	if store == nil {
		return m, nil
	}
	raw, err := store.Get(ctx, settings.KeyPasswordPolicy)
	if errors.Is(err, settings.ErrNotFound) {
		return m, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load password policy: %w", err)
	}
	var stored security.PasswordPolicy
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, fmt.Errorf("decode stored password policy: %w", err)
	}
	if err := Validate(stored); err != nil {
		return nil, fmt.Errorf("stored password policy is invalid: %w", err)
	}
	m.current = stored
	return m, nil
}

// Current returns the persisted policy, so changes are visible across API
// instances. A value copy is returned to keep callers from mutating the cache.
func (m *Manager) Current(ctx context.Context) (security.PasswordPolicy, error) {
	if m.store != nil {
		raw, err := m.store.Get(ctx, settings.KeyPasswordPolicy)
		if err == nil {
			var stored security.PasswordPolicy
			if err := json.Unmarshal(raw, &stored); err != nil {
				return security.PasswordPolicy{}, fmt.Errorf("decode stored password policy: %w", err)
			}
			if err := Validate(stored); err != nil {
				return security.PasswordPolicy{}, fmt.Errorf("stored password policy is invalid: %w", err)
			}
			return stored, nil
		}
		if !errors.Is(err, settings.ErrNotFound) {
			return security.PasswordPolicy{}, fmt.Errorf("load password policy: %w", err)
		}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current, nil
}

// Violations returns every stable CSAX Auth violation for the active policy.
func (m *Manager) Violations(ctx context.Context, password string) ([]string, error) {
	policy, err := m.Current(ctx)
	if err != nil {
		return nil, err
	}
	return policy.Validate(password), nil
}

// Update persists the full replacement before making it current in memory.
func (m *Manager) Update(ctx context.Context, next security.PasswordPolicy) error {
	if err := Validate(next); err != nil {
		return err
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("encode password policy: %w", err)
	}
	if m.store != nil {
		if err := m.store.Put(ctx, settings.KeyPasswordPolicy, raw); err != nil {
			return fmt.Errorf("save password policy: %w", err)
		}
	}
	m.mu.Lock()
	m.current = next
	m.mu.Unlock()
	return nil
}

// Validate prevents an override from weakening CSAX Auth's immutable engine
// baseline. Updates can enable composition checks and narrow the accepted
// length range; min 8 and max 72 remain enforced by the engine too.
func Validate(policy security.PasswordPolicy) error {
	base := security.DefaultPasswordPolicy
	if policy.MinLength < base.MinLength || policy.MinLength > base.MaxLength {
		return fmt.Errorf("min_length must be between %d and %d", base.MinLength, base.MaxLength)
	}
	if policy.MaxLength < policy.MinLength || policy.MaxLength > base.MaxLength {
		return fmt.Errorf("max_length must be between min_length and %d", base.MaxLength)
	}
	return nil
}
