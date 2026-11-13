package digest

import (
	"context"
	"testing"
	"time"

	"github.com/crydensync/api/settings"
)

func TestRuntimePersistsAndPublishesScheduleSettings(t *testing.T) {
	store := settings.NewMemoryStore()
	runtime, err := NewRuntime(context.Background(), store, DefaultScheduleSettings())
	if err != nil {
		t.Fatal(err)
	}

	next := ScheduleSettings{
		Enabled: true, DayOfWeek: "friday", Time: "16:30", Timezone: "Africa/Casablanca",
		Recipients: []string{"security@example.com"},
	}
	if err := runtime.Save(context.Background(), next); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// The runtime keeps its own copy of recipient data instead of retaining a
	// caller-owned slice that could change without a persisted update.
	next.Recipients[0] = "changed@example.com"
	got := runtime.Snapshot()
	if !got.Enabled || got.DayOfWeek != "friday" || got.Time != "16:30" || got.Timezone != "Africa/Casablanca" {
		t.Fatalf("Snapshot = %+v, want the saved weekly schedule", got)
	}
	if got.Recipients[0] != "security@example.com" {
		t.Fatalf("recipient = %q, want the saved value", got.Recipients[0])
	}

	reloaded, err := NewRuntime(context.Background(), store, DefaultScheduleSettings())
	if err != nil {
		t.Fatalf("NewRuntime from saved settings: %v", err)
	}
	if got := reloaded.Snapshot(); got.Timezone != "Africa/Casablanca" || got.Recipients[0] != "security@example.com" {
		t.Fatalf("reloaded settings = %+v, want the persisted schedule", got)
	}
}

func TestScheduleSettingsRejectInvalidTimezoneAndRecipients(t *testing.T) {
	base := DefaultScheduleSettings()
	for name, mutate := range map[string]func(*ScheduleSettings){
		"invalid weekday":             func(s *ScheduleSettings) { s.DayOfWeek = "someday" },
		"invalid time":                func(s *ScheduleSettings) { s.Time = "25:61" },
		"invalid timezone":            func(s *ScheduleSettings) { s.Timezone = "Mars/Olympus" },
		"invalid recipient":           func(s *ScheduleSettings) { s.Recipients = []string{"not an address"} },
		"duplicate recipient":         func(s *ScheduleSettings) { s.Recipients = []string{"a@example.com", "A@example.com"} },
		"delivery without recipients": func(s *ScheduleSettings) { s.DeliveryEnabled = true },
	} {
		t.Run(name, func(t *testing.T) {
			schedule := base
			schedule.Recipients = append([]string(nil), base.Recipients...)
			mutate(&schedule)
			if err := schedule.Validate(); err == nil {
				t.Fatal("Validate succeeded, want an error")
			}
		})
	}
}

func TestNextScheduledRunUsesTheSelectedWeekdayAndTimezone(t *testing.T) {
	schedule := DefaultScheduleSettings()
	schedule.Enabled = true
	schedule.DayOfWeek = "monday"
	schedule.Time = "09:00"
	schedule.Timezone = "America/New_York"

	for _, tc := range []struct {
		name string
		now  time.Time
		want time.Time
	}{
		{
			name: "later the same local morning",
			now:  time.Date(2026, time.November, 9, 8, 0, 0, 0, time.FixedZone("UTC", 0)),
			want: time.Date(2026, time.November, 9, 9, 0, 0, 0, mustLocation(t, "America/New_York")),
		},
		{
			name: "after the selected time rolls to next week",
			now:  time.Date(2026, time.November, 9, 15, 0, 0, 0, mustLocation(t, "America/New_York")),
			want: time.Date(2026, time.November, 16, 9, 0, 0, 0, mustLocation(t, "America/New_York")),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := nextScheduledRun(schedule, tc.now)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Equal(tc.want) {
				t.Errorf("nextScheduledRun = %s, want %s", got, tc.want)
			}
		})
	}
}

func mustLocation(t *testing.T, name string) *time.Location {
	t.Helper()
	location, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return location
}
