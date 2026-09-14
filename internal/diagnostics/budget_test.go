package diagnostics

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/ghapi"
)

type archiveClient struct {
	archive []byte
	err     error
	calls   atomic.Int64
}

func (c *archiveClient) Host() string { return "github.com" }

func (c *archiveClient) GetBytesLimited(_ context.Context, _ string, limit int64) ([]byte, error) {
	c.calls.Add(1)
	if c.err != nil {
		return nil, c.err
	}
	if int64(len(c.archive)) > limit {
		return nil, ghapi.ErrResponseTooLarge
	}
	return c.archive, nil
}

func emptyArchive(t *testing.T) []byte {
	t.Helper()
	var buffer bytes.Buffer
	if err := zip.NewWriter(&buffer).Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestInspectReportsBudgetSkips(t *testing.T) {
	for _, test := range []struct {
		name          string
		limits        Limits
		firstSucceeds bool
	}{
		{"repository count", Limits{MaxRepositories: 1}, true},
		{"compressed bytes", Limits{MaxBytes: int64(len(emptyArchive(t)))}, true},
		{"oversized archive", Limits{MaxBytes: 1}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &archiveClient{archive: emptyArchive(t)}
			fetcher := NewFetcher(client, test.limits)
			_, err := fetcher.Inspect(context.Background(), "org", "one", 1)
			if test.firstSucceeds && err != nil {
				t.Fatal(err)
			}
			if !test.firstSucceeds && !errors.Is(err, ErrBudgetExhausted) {
				t.Fatalf("oversized archive must be incomplete, got %v", err)
			}
			_, err = fetcher.Inspect(context.Background(), "org", "two", 2)
			if !errors.Is(err, ErrBudgetExhausted) {
				t.Fatalf("budget skip must not look clean, got %v", err)
			}
			if got := client.calls.Load(); got != 1 {
				t.Fatalf("exhausted budget made %d requests, want 1", got)
			}
		})
	}
}

func TestInspectReportsUnavailableLogs(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound} {
		apiErr := &ghapi.StatusError{StatusCode: status, Message: "logs unavailable"}
		fetcher := NewFetcher(&archiveClient{err: apiErr}, Limits{})
		_, err := fetcher.Inspect(context.Background(), "org", "repo", 1)
		if !errors.Is(err, apiErr) {
			t.Fatalf("unread logs must propagate their error, got %v", err)
		}
	}
}

func TestConcurrentInspectionHonorsTotalBytes(t *testing.T) {
	archive := emptyArchive(t)
	client := &archiveClient{archive: archive}
	fetcher := NewFetcher(client, Limits{MaxRepositories: 100, MaxBytes: int64(2 * len(archive))})
	var wait sync.WaitGroup
	var completed atomic.Int64
	for index := range 20 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := fetcher.Inspect(context.Background(), "org", "repo", int64(index))
			if err == nil {
				completed.Add(1)
			} else if !errors.Is(err, ErrBudgetExhausted) {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wait.Wait()
	if completed.Load() != 2 || client.calls.Load() != 2 || fetcher.bytesRead.Load() != int64(2*len(archive)) {
		t.Fatalf("budget overspent: completed=%d requests=%d bytes=%d",
			completed.Load(), client.calls.Load(), fetcher.bytesRead.Load())
	}
}

func TestCancelledInspectionDoesNotDownload(t *testing.T) {
	client := &archiveClient{archive: emptyArchive(t)}
	fetcher := NewFetcher(client, Limits{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fetcher.Inspect(ctx, "org", "repo", 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if client.calls.Load() != 0 {
		t.Fatal("cancelled inspection downloaded logs")
	}
}

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
