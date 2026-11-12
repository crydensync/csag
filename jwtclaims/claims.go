// Package jwtclaims manages global source-to-claim mappings layered over the
// API's existing per-user metadata claims.
package jwtclaims

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/crydensync/api/settings"
	"github.com/crydensync/api/usermeta"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/token"
)

const SettingsKey = "jwt_claims"

type Mapping struct {
	Claim  string `json:"claim"`
	Source string `json:"source"`
}

type Config struct {
	Mappings []Mapping `json:"mappings"`
}

var ErrInvalidMapping = errors.New("jwtclaims: invalid mapping")

func (c Config) Validate() error {
	seen := make(map[string]struct{}, len(c.Mappings))
	for _, mapping := range c.Mappings {
		if err := usermeta.ValidateKey(mapping.Claim); err != nil {
			return fmt.Errorf("%w: claim %q is not a valid claim name", ErrInvalidMapping, mapping.Claim)
		}
		if token.IsReservedClaim(mapping.Claim) || mapping.Claim == usermeta.RoleClaim {
			return fmt.Errorf("%w: claim %q is reserved", ErrInvalidMapping, mapping.Claim)
		}
		if _, ok := seen[mapping.Claim]; ok {
			return fmt.Errorf("%w: claim %q is mapped more than once", ErrInvalidMapping, mapping.Claim)
		}
		seen[mapping.Claim] = struct{}{}
		if !validSource(mapping.Source) {
			return fmt.Errorf("%w: source %q is not supported", ErrInvalidMapping, mapping.Source)
		}
	}
	if len(c.Mappings) > 32 {
		return fmt.Errorf("%w: at most 32 mappings are allowed", ErrInvalidMapping)
	}
	return nil
}

func validSource(source string) bool {
	switch source {
	case "user.id", "user.email", "user.created_at", "user.updated_at":
		return true
	}
	if strings.HasPrefix(source, "metadata.") {
		return usermeta.ValidateKey(strings.TrimPrefix(source, "metadata.")) == nil
	}
	return false
}

func Decode(raw []byte) (Config, error) {
	var config Config
	if err := json.Unmarshal(raw, &config); err != nil {
		return config, fmt.Errorf("jwtclaims: decoding mappings: %w", err)
	}
	if config.Mappings == nil {
		config.Mappings = []Mapping{}
	}
	if err := config.Validate(); err != nil {
		return config, err
	}
	return config, nil
}

// Provider adds configured global mappings to user metadata and the operator
// role. Per-user metadata wins on collisions; the operator role always wins.
type Provider struct {
	Users     store.UserStore
	Metadata  usermeta.Store
	Operators usermeta.RoleLookup
	Store     settings.Store
}

func (p *Provider) AccessTokenClaims(ctx context.Context, userID string) (map[string]any, error) {
	claims, err := usermeta.ClaimsProvider(p.Metadata, p.Operators).AccessTokenClaims(ctx, userID)
	if err != nil {
		return nil, err
	}
	config, err := p.load(ctx)
	if err != nil {
		return nil, err
	}
	if len(config.Mappings) == 0 {
		return claims, nil
	}

	var user store.User
	userLoaded := false
	for _, mapping := range config.Mappings {
		var value any
		present := true
		switch mapping.Source {
		case "user.id":
			value = userID
		case "user.email", "user.created_at", "user.updated_at":
			if p.Users == nil {
				return nil, errors.New("jwtclaims: user store is not configured")
			}
			if !userLoaded {
				user, err = p.Users.GetByID(ctx, userID)
				if err != nil {
					return nil, err
				}
				userLoaded = true
			}
			switch mapping.Source {
			case "user.email":
				value = user.Email
			case "user.created_at":
				value = user.CreatedAt.UTC()
			case "user.updated_at":
				value = user.UpdatedAt.UTC()
			}
		default:
			key := strings.TrimPrefix(mapping.Source, "metadata.")
			if claims != nil {
				value, present = claims[key]
			} else {
				present = false
			}
		}
		if !present {
			continue
		}
		if claims == nil {
			claims = make(map[string]any)
		}
		if _, exists := claims[mapping.Claim]; !exists {
			claims[mapping.Claim] = value
		}
	}
	return claims, nil
}

func (p *Provider) load(ctx context.Context) (Config, error) {
	if p.Store == nil {
		return Config{Mappings: []Mapping{}}, nil
	}
	raw, err := p.Store.Get(ctx, SettingsKey)
	if errors.Is(err, settings.ErrNotFound) {
		return Config{Mappings: []Mapping{}}, nil
	}
	if err != nil {
		return Config{}, err
	}
	return Decode(raw)
}

func (p *Provider) Save(ctx context.Context, config Config) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if p.Store == nil {
		return errors.New("jwtclaims: settings store is not configured")
	}
	if config.Mappings == nil {
		config.Mappings = []Mapping{}
	}
	raw, err := json.Marshal(config)
	if err != nil {
		return err
	}
	return p.Store.Put(ctx, SettingsKey, raw)
}

// Read returns the validated runtime configuration, or an empty mapping list.
func (p *Provider) Read(ctx context.Context) (Config, error) {
	return p.load(ctx)
}

var _ token.ClaimsProvider = (*Provider)(nil)
