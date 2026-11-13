package aiprovider

import (
	"context"
	"errors"
	"sync"
	"time"

	crydenai "github.com/crydensync/cryden/v2/ai"
)

var ErrRPMExceeded = errors.New("aiprovider: configured requests-per-minute limit reached")

type UsageStat struct {
	Kind          string    `json:"kind"`
	Model         string    `json:"model"`
	Requests      uint64    `json:"requests"`
	Succeeded     uint64    `json:"succeeded"`
	Failed        uint64    `json:"failed"`
	RateLimited   uint64    `json:"rate_limited"`
	LastRequestAt time.Time `json:"last_request_at,omitempty"`
	AverageMS     int64     `json:"average_ms"`
}

type usageCounter struct {
	stat    UsageStat
	totalMS int64
}

var processUsage = struct {
	sync.Mutex
	byModel map[string]*usageCounter
}{byModel: make(map[string]*usageCounter)}

// UsageSnapshot reports actual provider calls since this API process started.
func UsageSnapshot() []UsageStat {
	processUsage.Lock()
	defer processUsage.Unlock()
	result := make([]UsageStat, 0, len(processUsage.byModel))
	for _, counter := range processUsage.byModel {
		stat := counter.stat
		if stat.Requests > 0 {
			stat.AverageMS = counter.totalMS / int64(stat.Requests)
		}
		result = append(result, stat)
	}
	return result
}

type meteredProvider struct {
	base        crydenai.LLMProvider
	kind        string
	model       string
	rpm         int
	mu          sync.Mutex
	windowStart time.Time
	windowCalls int
}

func meterProvider(base crydenai.LLMProvider, kind, model string, rpm int) crydenai.LLMProvider {
	return &meteredProvider{base: base, kind: kind, model: model, rpm: rpm}
}

func (p *meteredProvider) allow() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if p.windowStart.IsZero() || now.Sub(p.windowStart) >= time.Minute {
		p.windowStart = now
		p.windowCalls = 0
	}
	if p.windowCalls >= p.rpm {
		processUsage.Lock()
		counter := usageCounterFor(p.kind, p.model)
		counter.stat.RateLimited++
		processUsage.Unlock()
		return false
	}
	p.windowCalls++
	return true
}

func (p *meteredProvider) ParseQueryIntent(ctx context.Context, question string) (crydenai.QueryIntent, error) {
	if !p.allow() {
		return crydenai.QueryIntent{}, ErrRPMExceeded
	}
	started := time.Now()
	intent, err := p.base.ParseQueryIntent(ctx, question)
	recordUsage(p.kind, p.model, started, err)
	return intent, err
}

func (p *meteredProvider) ComposeAnswer(ctx context.Context, question string, result crydenai.QueryResult) (string, error) {
	composer, ok := p.base.(interface {
		ComposeAnswer(context.Context, string, crydenai.QueryResult) (string, error)
	})
	if !ok {
		return "", errors.New("aiprovider: configured provider does not support answer composition")
	}
	if !p.allow() {
		return "", ErrRPMExceeded
	}
	started := time.Now()
	answer, err := composer.ComposeAnswer(ctx, question, result)
	recordUsage(p.kind, p.model, started, err)
	return answer, err
}

func usageCounterFor(kind, model string) *usageCounter {
	key := kind + "\x00" + model
	counter := processUsage.byModel[key]
	if counter == nil {
		counter = &usageCounter{stat: UsageStat{Kind: kind, Model: model}}
		processUsage.byModel[key] = counter
	}
	return counter
}

func recordUsage(kind, model string, started time.Time, err error) {
	processUsage.Lock()
	defer processUsage.Unlock()
	counter := usageCounterFor(kind, model)
	finished := time.Now()
	counter.stat.Requests++
	if err != nil {
		counter.stat.Failed++
	} else {
		counter.stat.Succeeded++
	}
	counter.stat.LastRequestAt = finished.UTC()
	counter.totalMS += finished.Sub(started).Milliseconds()
}
