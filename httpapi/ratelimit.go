package httpapi

import (
	"net/http"
	"sync"
	"time"
)

// EdgeRateLimiter is a coarse, per-IP request limiter applied to
// EVERY request, on top of (not instead of) the engine's own
// per-user login/signup rate limiting. The engine's limiter protects
// specific auth operations from credential-stuffing; this one
// protects the whole API surface from being hammered generally.
//
// Same honest limitation as the engine's InMemoryRateLimiter: this is
// in-memory, per-process. It resets on restart and does NOT share
// state across multiple instances behind a load balancer — fine for
// a single-instance deployment, not sufficient once you scale
// horizontally. A Redis-backed version is the natural upgrade path
// later, not built here.
type EdgeRateLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	counters map[string]*windowCounter
}

type windowCounter struct {
	count     int
	windowEnd time.Time
}

// WidgetUserRateLimiter bounds paid Ask-AI calls per verified account. Like
// EdgeRateLimiter, it is process-local; Redis-backed sharing is a separate
// deployment concern.
type WidgetUserRateLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	counters map[string]*windowCounter
	checks   uint64
}

func NewWidgetUserRateLimiter(limit int, window time.Duration) *WidgetUserRateLimiter {
	if limit < 1 || window <= 0 {
		return nil
	}
	return &WidgetUserRateLimiter{
		limit:    limit,
		window:   window,
		counters: make(map[string]*windowCounter),
	}
}

func (l *WidgetUserRateLimiter) allow(userID string) bool {
	if l == nil || userID == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	c, ok := l.counters[userID]
	if !ok || !now.Before(c.windowEnd) {
		l.counters[userID] = &windowCounter{count: 1, windowEnd: now.Add(l.window)}
	} else if c.count >= l.limit {
		return false
	} else {
		c.count++
	}

	// Expired identities are removed gradually so the map stays bounded
	// without a cleanup goroutine or work on every request.
	l.checks++
	if l.checks%256 == 0 {
		for id, counter := range l.counters {
			if !now.Before(counter.windowEnd) {
				delete(l.counters, id)
			}
		}
	}
	return true
}

// WithWidgetUserRateLimit runs after RequireAuth so the key is the user id
// verified from the bearer token, never a body or query parameter.
func WithWidgetUserRateLimit(limiter *WidgetUserRateLimiter, next http.HandlerFunc) http.HandlerFunc {
	if limiter == nil {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if !limiter.allow(UserIDFromContext(r)) {
			writeErr(w, errWidgetRateLimited)
			return
		}
		next(w, r)
	}
}

func NewEdgeRateLimiter(limit int, window time.Duration) *EdgeRateLimiter {
	return &EdgeRateLimiter{
		limit:    limit,
		window:   window,
		counters: make(map[string]*windowCounter),
	}
}

func (l *EdgeRateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	c, ok := l.counters[key]
	if !ok || now.After(c.windowEnd) {
		l.counters[key] = &windowCounter{count: 1, windowEnd: now.Add(l.window)}
		return true
	}
	if c.count >= l.limit {
		return false
	}
	c.count++
	return true
}

// WithEdgeRateLimit wraps a handler, rejecting requests over the
// per-IP limit with 429. CORS preflight (OPTIONS) requests are not
// counted — browsers send these automatically and shouldn't consume
// a caller's real request budget.
func WithEdgeRateLimit(limiter *EdgeRateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		if !limiter.allow(CallerIP(r)) {
			writeErr(w, errEdgeRateLimited)
			return
		}
		next.ServeHTTP(w, r)
	})
}
