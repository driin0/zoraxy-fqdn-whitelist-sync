package main

import (
	"sync"
	"time"
)

type StatusStore struct {
	mu      sync.RWMutex
	lastRun time.Time
	results []ReconcileResult
}

// Set publishes the results of a reconcile cycle. The caller must hand over a
// slice (and the ReconcileResult values/maps within it) that it will not
// mutate afterwards — Set stores the slice header as-is, it does not copy.
func (s *StatusStore) Set(results []ReconcileResult, when time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results = results
	s.lastRun = when
}

// Snapshot returns the most recently published results slice by reference
// (no copy). This is safe only because the reconciler allocates a fresh
// slice/maps every cycle via Reconciler.All/Reconciler.Rule and never mutates
// a ReconcileResult after handing it to Set. If a future change starts
// mutating a published ReconcileResult in place (e.g. appending to its
// Added/Removed/Errors slices on a later cycle instead of building new
// ones), that mutation would race with concurrent readers of this snapshot.
func (s *StatusStore) Snapshot() (time.Time, []ReconcileResult) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastRun, s.results
}
