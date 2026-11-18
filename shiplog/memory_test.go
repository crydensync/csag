package shiplog

import (
	"context"
	"testing"

	"github.com/crydensync/cryden/v2/logger"
)

func TestMemoryStoreLimitRetainsNewestRecords(t *testing.T) {
	store := NewMemoryStoreLimit(2)
	sink := NewLogger(store)
	sink.Info("first", nil)
	sink.Info("second", nil)
	sink.Info("third", nil)

	if got := store.Count(); got != 2 {
		t.Fatalf("Count = %d, want 2 retained records", got)
	}
	rows, err := store.List(context.Background(), logger.LevelDebug, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Message != "third" || rows[1].Message != "second" {
		t.Fatalf("retained rows = %+v, want third then second", rows)
	}
}
