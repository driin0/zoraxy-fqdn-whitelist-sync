package main

import (
	"testing"
	"time"
)

func TestStatusStoreRoundTrip(t *testing.T) {
	s := &StatusStore{}
	when := time.Unix(1_700_000_000, 0)
	s.Set([]ReconcileResult{{RuleID: "default", Added: []string{"203.0.113.7"}}}, when)

	got, results := s.Snapshot()
	if !got.Equal(when) {
		t.Errorf("lastRun = %v, want %v", got, when)
	}
	if len(results) != 1 || results[0].RuleID != "default" {
		t.Errorf("results = %+v, unexpected", results)
	}
}
