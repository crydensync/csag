package digest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/crydensync/api/settings"
)

const SettingsKey = "digest_schedule"

var ErrDeliveryUnavailable = errors.New("digest: email delivery is not configured")

// ScheduleSettings controls when reports are generated and whether the
// configured host sender receives them. The API does not own a mail provider.
type ScheduleSettings struct {
	Enabled         bool     `json:"enabled"`
	DayOfWeek       string   `json:"day_of_week"`
	Time            string   `json:"time"`
	Timezone        string   `json:"timezone"`
	Recipients      []string `json:"recipients"`
	DeliveryEnabled bool     `json:"delivery_enabled"`
	// IntervalHours preserves the deployment's legacy interval setting. New
	// schedules use the weekly day, time, and timezone fields instead.
	IntervalHours int `json:"interval_hours,omitempty"`
}

func (s ScheduleSettings) Validate() error {
	if s.IntervalHours < 0 || s.IntervalHours > 8760 {
		return fmt.Errorf("digest: interval_hours must be between 0 and 8760")
	}
	if _, ok := weekdays[strings.ToLower(s.DayOfWeek)]; !ok {
		return fmt.Errorf("digest: day_of_week must be a weekday name")
	}
	if parsed, err := time.Parse("15:04", s.Time); err != nil || parsed.Format("15:04") != s.Time {
		return fmt.Errorf("digest: time must use HH:MM in 24-hour format")
	}
	if _, err := time.LoadLocation(s.Timezone); err != nil {
		return fmt.Errorf("digest: timezone must be a valid IANA timezone")
	}
	if len(s.Recipients) > 20 {
		return fmt.Errorf("digest: no more than 20 recipients are allowed")
	}
	seen := make(map[string]struct{}, len(s.Recipients))
	for _, recipient := range s.Recipients {
		address, err := mail.ParseAddress(recipient)
		if err != nil || address.Address != recipient || len(recipient) > 254 {
			return fmt.Errorf("digest: each recipient must be a valid email address")
		}
		key := strings.ToLower(recipient)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("digest: recipients must not contain duplicates")
		}
		seen[key] = struct{}{}
	}
	if s.DeliveryEnabled && len(s.Recipients) == 0 {
		return fmt.Errorf("digest: at least one recipient is required when delivery is enabled")
	}
	return nil
}

// DefaultScheduleSettings is the dormant weekly schedule used when no
// environment or operator setting has enabled digest generation.
func DefaultScheduleSettings() ScheduleSettings {
	return ScheduleSettings{DayOfWeek: "monday", Time: "09:00", Timezone: "UTC", Recipients: []string{}}
}

var weekdays = map[string]time.Weekday{
	"sunday": time.Sunday, "monday": time.Monday, "tuesday": time.Tuesday,
	"wednesday": time.Wednesday, "thursday": time.Thursday, "friday": time.Friday, "saturday": time.Saturday,
}

// DeliverySender is implemented by a host that has a real outbound email
// provider. A nil sender leaves history generation available and delivery off.
type DeliverySender interface {
	SendDigest(context.Context, string, string, string) error
}

type Runtime struct {
	store  settings.Store
	mu     sync.RWMutex
	active ScheduleSettings
}

func NewRuntime(ctx context.Context, store settings.Store, fallback ScheduleSettings) (*Runtime, error) {
	if err := fallback.Validate(); err != nil {
		return nil, err
	}
	r := &Runtime{store: store, active: cloneScheduleSettings(fallback)}
	if store == nil {
		return r, nil
	}
	raw, err := store.Get(ctx, SettingsKey)
	if errors.Is(err, settings.ErrNotFound) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	var saved ScheduleSettings
	if err := json.Unmarshal(raw, &saved); err != nil {
		return nil, fmt.Errorf("digest: decoding schedule settings: %w", err)
	}
	if err := saved.Validate(); err != nil {
		return nil, err
	}
	r.active = cloneScheduleSettings(saved)
	return r, nil
}

func (r *Runtime) Snapshot() ScheduleSettings {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return cloneScheduleSettings(r.active)
}

func (r *Runtime) Interval() time.Duration {
	if r == nil {
		return 0
	}
	s := r.Snapshot()
	if !s.Enabled {
		return 0
	}
	return time.Duration(s.IntervalHours) * time.Hour
}

func (r *Runtime) Save(ctx context.Context, next ScheduleSettings) error {
	if err := next.Validate(); err != nil {
		return err
	}
	if r == nil || r.store == nil {
		return errors.New("digest: settings store is not configured")
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err := r.store.Put(ctx, SettingsKey, raw); err != nil {
		return err
	}
	r.mu.Lock()
	r.active = cloneScheduleSettings(next)
	r.mu.Unlock()
	return nil
}

func cloneScheduleSettings(s ScheduleSettings) ScheduleSettings {
	s.Recipients = append([]string(nil), s.Recipients...)
	if s.Recipients == nil {
		s.Recipients = []string{}
	}
	return s
}
