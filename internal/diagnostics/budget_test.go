package diagnostics

import (
	"sync"
	"testing"
)

// The repository budget has to be a reservation. Checking the counter and then
// incrementing it lets every concurrent worker pass the check before any of
// them increments, so the cap could be exceeded by roughly the worker count
// and a scan would download far more log data than the operator allowed.
func TestRepositoryBudgetIsReservedAtomically(t *testing.T) {
	const limit = 5
	fetcher := NewFetcher(nil, Limits{MaxRepositories: limit, MaxBytes: 1 << 20})

	var wait sync.WaitGroup
	granted := make(chan struct{}, 200)
	for worker := 0; worker < 200; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if fetcher.reserve() {
				granted <- struct{}{}
			}
		}()
	}
	wait.Wait()
	close(granted)

	if count := len(granted); count != limit {
		t.Fatalf("%d reservations were granted, want %d; the budget must not be exceeded under concurrency", count, limit)
	}
}

// Once the byte budget is spent there is nothing left to download, so no
// further repository slots should be consumed.
func TestExhaustedByteBudgetStopsInspection(t *testing.T) {
	fetcher := NewFetcher(nil, Limits{MaxRepositories: 10, MaxBytes: 1024})
	fetcher.bytesRead.Store(1024)

	if remaining := fetcher.remainingBytes(); remaining != 0 {
		t.Fatalf("remaining bytes = %d, want 0", remaining)
	}
	if exhausted, message := fetcher.Budget(); !exhausted || message == "" {
		t.Fatal("a spent byte budget must be reported as exhausted, with an explanation")
	}
}

// Overspending is reported as zero remaining rather than a negative budget,
// which would otherwise be passed to a download as an unbounded limit.
func TestOverspentByteBudgetDoesNotReportNegativeRemaining(t *testing.T) {
	fetcher := NewFetcher(nil, Limits{MaxRepositories: 10, MaxBytes: 1024})
	fetcher.bytesRead.Store(4096)

	if remaining := fetcher.remainingBytes(); remaining != 0 {
		t.Fatalf("remaining bytes = %d, want 0", remaining)
	}
}
