package shiplog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/crydensync/api/settings"
	"github.com/crydensync/cryden/v2/logger"
)

const SettingsKey = "cloud_logging"

// RuntimeSettings controls the API's local redacted log archive. Provider
// credentials and redaction secrets remain deployment configuration.
type RuntimeSettings struct {
	Enabled  bool   `json:"enabled"`
	MinLevel string `json:"min_level"`
}

func (s RuntimeSettings) Validate() error {
	if _, err := logger.ParseLevel(s.MinLevel); err != nil {
		return fmt.Errorf("cloud logging: invalid minimum level %q", s.MinLevel)
	}
	return nil
}

// Runtime persists operator settings and publishes the active copy atomically
// to the logger used by the engine.
type Runtime struct {
	store  settings.Store
	mu     sync.RWMutex
	active RuntimeSettings
}

func NewRuntime(ctx context.Context, store settings.Store, fallback RuntimeSettings) (*Runtime, error) {
	if err := fallback.Validate(); err != nil {
		return nil, err
	}
	r := &Runtime{store: store, active: fallback}
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
	var saved RuntimeSettings
	if err := json.Unmarshal(raw, &saved); err != nil {
		return nil, fmt.Errorf("cloud logging: decoding runtime settings: %w", err)
	}
	if err := saved.Validate(); err != nil {
		return nil, err
	}
	r.active = saved
	return r, nil
}

func (r *Runtime) Snapshot() RuntimeSettings {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.active
}

func (r *Runtime) Save(ctx context.Context, next RuntimeSettings) error {
	if err := next.Validate(); err != nil {
		return err
	}
	if r == nil || r.store == nil {
		return errors.New("cloud logging: settings store is not configured")
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err := r.store.Put(ctx, SettingsKey, raw); err != nil {
		return err
	}
	r.mu.Lock()
	r.active = next
	r.mu.Unlock()
	return nil
}

// RuntimeLogger applies the current enable switch and minimum level without a
// server restart, then forwards through the preconfigured redacting sink.
type RuntimeLogger struct {
	Runtime *Runtime
	Sink    logger.Logger
}

func (l *RuntimeLogger) Log(ctx context.Context, level logger.Level, message string, fields map[string]string) {
	if l == nil || l.Runtime == nil || l.Sink == nil {
		return
	}
	settings := l.Runtime.Snapshot()
	minimum, err := logger.ParseLevel(settings.MinLevel)
	if !settings.Enabled || err != nil || level < minimum {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if sink, ok := l.Sink.(logger.ContextLogger); ok {
		sink.Log(ctx, level, message, fields)
		return
	}
	switch level {
	case logger.LevelDebug:
		l.Sink.Debug(message, fields)
	case logger.LevelInfo:
		l.Sink.Info(message, fields)
	case logger.LevelWarn:
		l.Sink.Warn(message, fields)
	default:
		l.Sink.Error(message, fields)
	}
}

func (l *RuntimeLogger) Debug(message string, fields map[string]string) {
	l.Log(context.Background(), logger.LevelDebug, message, fields)
}
func (l *RuntimeLogger) Info(message string, fields map[string]string) {
	l.Log(context.Background(), logger.LevelInfo, message, fields)
}
func (l *RuntimeLogger) Warn(message string, fields map[string]string) {
	l.Log(context.Background(), logger.LevelWarn, message, fields)
}
func (l *RuntimeLogger) Error(message string, fields map[string]string) {
	l.Log(context.Background(), logger.LevelError, message, fields)
}

var _ logger.ContextLogger = (*RuntimeLogger)(nil)
