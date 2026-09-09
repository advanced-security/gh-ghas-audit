package ghapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestClient builds a Client aimed at a test server. It constructs the
// struct directly so no test-only option has to exist in the public API.
func newTestClient(server *httptest.Server, store ResponseCache) *Client {
	return &Client{
		http:      server.Client(),
		host:      "github.com",
		restBase:  server.URL + "/",
		cache:     store,
		stats:     &Stats{},
		semaphore: make(chan struct{}, 4),
	}
}

// TestMain shortens the retry schedule so the suite does not spend most of its
// time asleep in exponential backoff.
func TestMain(m *testing.M) {
	backoffBase = time.Millisecond
	defaultSecondaryWait = 10 * time.Millisecond
	os.Exit(m.Run())
}

// GitHub can return a secondary rate limit with neither Retry-After nor an
// exhausted X-RateLimit-Remaining header, leaving the body as the only signal.
// Misreading that as a permission error would turn a transient throttle into a
// repository health verdict.
func TestSecondaryRateLimitIsDetectedFromTheBody(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		if requests == 1 {
			writer.Header().Set("X-RateLimit-Remaining", "4821")
			writer.WriteHeader(http.StatusForbidden)
			fmt.Fprint(writer, `{"message":"You have exceeded a secondary rate limit. Please wait a few minutes before you try again."}`)
			return
		}
		fmt.Fprint(writer, `{"value":"ok"}`)
	}))
	defer server.Close()

	client := newTestClient(server, nil)

	var payload struct {
		Value string `json:"value"`
	}
	if err := client.GetJSON(context.Background(), "thing", &payload); err != nil {
		t.Fatalf("a secondary rate limit should be retried: %v", err)
	}
	if payload.Value != "ok" || requests != 2 {
		t.Fatalf("value = %q after %d requests", payload.Value, requests)
	}
	if client.Stats().RateLimitWaits.Load() != 1 {
		t.Fatalf("rate limit waits = %d, want 1", client.Stats().RateLimitWaits.Load())
	}
}

// Once the retry budget is exhausted, the error must be identifiable as a rate
// limit so callers do not record it as a repository's health.
func TestExhaustedRateLimitIsReportedAsRateLimited(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-RateLimit-Remaining", "4821")
		writer.WriteHeader(http.StatusForbidden)
		fmt.Fprint(writer, `{"message":"You have exceeded a secondary rate limit"}`)
	}))
	defer server.Close()

	err := newTestClient(server, nil).GetJSON(context.Background(), "thing", &struct{}{})
	if err == nil {
		t.Fatal("expected an error after exhausting retries")
	}
	if !IsRateLimited(err) {
		t.Fatalf("error should be identifiable as a rate limit, got %v", err)
	}
	if IsForbidden(err) {
		t.Fatal("a rate limit must not be reported as a permission problem")
	}
}

// Log archives are large and read once, so they must not be written to the
// cache where they would dominate its size.
func TestLogArchivesBypassTheCache(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("ETag", `"logs-v1"`)
		fmt.Fprint(writer, "PK-archive-bytes")
	}))
	defer server.Close()

	store := newMemoryCache()
	client := newTestClient(server, store)

	body, err := client.GetBytes(context.Background(), "repos/o/r/actions/runs/1/logs")
	if err != nil {
		t.Fatalf("GetBytes returned an error: %v", err)
	}
	if string(body) != "PK-archive-bytes" {
		t.Fatalf("body = %q", body)
	}

	store.mu.Lock()
	cached := len(store.entries)
	store.mu.Unlock()
	if cached != 0 {
		t.Fatalf("log archives must not be cached, found %d entries", cached)
	}
}

// memoryCache is a minimal in-memory ResponseCache for tests.
type memoryCache struct {
	mu      sync.Mutex
	entries map[string][2]string
}

func newMemoryCache() *memoryCache {
	return &memoryCache{entries: map[string][2]string{}}
}

func (m *memoryCache) Get(key string) (string, []byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.entries[key]
	if !ok {
		return "", nil, false
	}
	return entry[0], []byte(entry[1]), true
}

func (m *memoryCache) Put(key string, etag string, body []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[key] = [2]string{etag, string(body)}
}

func TestGetJSONDecodesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(writer, `{"state":"configured","languages":["go"]}`)
	}))
	defer server.Close()

	client := newTestClient(server, nil)

	var payload struct {
		State     string   `json:"state"`
		Languages []string `json:"languages"`
	}
	if err := client.GetJSON(context.Background(), "repos/o/r/code-scanning/default-setup", &payload); err != nil {
		t.Fatalf("GetJSON returned an error: %v", err)
	}
	if payload.State != "configured" || len(payload.Languages) != 1 {
		t.Fatalf("decoded payload = %+v", payload)
	}
}

func TestPaginationFollowsLinkHeader(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Query().Get("page") {
		case "", "1":
			writer.Header().Set("Link", fmt.Sprintf(`<%s/items?page=2>; rel="next", <%s/items?page=2>; rel="last"`, server.URL, server.URL))
			fmt.Fprint(writer, `[{"name":"one"}]`)
		case "2":
			fmt.Fprint(writer, `[{"name":"two"}]`)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := newTestClient(server, nil)

	var pages int
	var names []string
	err := client.GetPaginatedJSON(context.Background(), "items", func(page []byte) error {
		pages++
		var batch []struct {
			Name string `json:"name"`
		}
		if err := decodeJSON(page, &batch); err != nil {
			return err
		}
		for _, item := range batch {
			names = append(names, item.Name)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("GetPaginatedJSON returned an error: %v", err)
	}
	if pages != 2 || len(names) != 2 || names[0] != "one" || names[1] != "two" {
		t.Fatalf("pagination collected %d pages and names %v", pages, names)
	}
}

// A 304 response must be served from cache and counted as a cache hit, because
// conditional requests are what make repeated enterprise scans affordable.
func TestConditionalRequestServesFromCache(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Header.Get("If-None-Match") == `"v1"` {
			writer.WriteHeader(http.StatusNotModified)
			return
		}
		writer.Header().Set("ETag", `"v1"`)
		fmt.Fprint(writer, `{"value":"fresh"}`)
	}))
	defer server.Close()

	store := newMemoryCache()
	client := newTestClient(server, store)

	var first struct {
		Value string `json:"value"`
	}
	if err := client.GetJSON(context.Background(), "thing", &first); err != nil {
		t.Fatalf("first request failed: %v", err)
	}

	var second struct {
		Value string `json:"value"`
	}
	if err := client.GetJSON(context.Background(), "thing", &second); err != nil {
		t.Fatalf("second request failed: %v", err)
	}

	if second.Value != "fresh" {
		t.Fatalf("cached body was not returned, got %q", second.Value)
	}
	if requests != 2 {
		t.Fatalf("expected two HTTP requests, got %d", requests)
	}
	if client.Stats().CacheHits.Load() != 1 {
		t.Fatalf("cache hits = %d, want 1", client.Stats().CacheHits.Load())
	}
}

func TestPrimaryRateLimitIsRetriedAfterReset(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		if requests == 1 {
			writer.Header().Set("X-RateLimit-Remaining", "0")
			writer.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(-time.Minute).Unix()))
			writer.WriteHeader(http.StatusForbidden)
			fmt.Fprint(writer, `{"message":"API rate limit exceeded"}`)
			return
		}
		fmt.Fprint(writer, `{"value":"ok"}`)
	}))
	defer server.Close()

	client := newTestClient(server, nil)

	var payload struct {
		Value string `json:"value"`
	}
	if err := client.GetJSON(context.Background(), "thing", &payload); err != nil {
		t.Fatalf("rate limited request should be retried: %v", err)
	}
	if payload.Value != "ok" || requests != 2 {
		t.Fatalf("value = %q after %d requests", payload.Value, requests)
	}
	if client.Stats().RateLimitWaits.Load() != 1 {
		t.Fatalf("rate limit waits = %d, want 1", client.Stats().RateLimitWaits.Load())
	}
}

func TestSecondaryRateLimitHonoursRetryAfter(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		if requests == 1 {
			writer.Header().Set("Retry-After", "1")
			writer.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(writer, `{"message":"You have exceeded a secondary rate limit"}`)
			return
		}
		fmt.Fprint(writer, `{"value":"ok"}`)
	}))
	defer server.Close()

	client := newTestClient(server, nil)

	started := time.Now()
	var payload struct {
		Value string `json:"value"`
	}
	if err := client.GetJSON(context.Background(), "thing", &payload); err != nil {
		t.Fatalf("secondary rate limit should be retried: %v", err)
	}
	if elapsed := time.Since(started); elapsed < time.Second {
		t.Fatalf("Retry-After was not honoured, waited only %v", elapsed)
	}
}

// A plain 403 that is not a rate limit must fail fast rather than sleeping,
// otherwise an unlicensed repository would stall the whole scan.
func TestPlainForbiddenIsNotTreatedAsRateLimit(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writer.Header().Set("X-RateLimit-Remaining", "4999")
		writer.WriteHeader(http.StatusForbidden)
		fmt.Fprint(writer, `{"message":"Advanced Security must be enabled for this repository"}`)
	}))
	defer server.Close()

	client := newTestClient(server, nil)

	err := client.GetJSON(context.Background(), "thing", &struct{}{})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !IsForbidden(err) {
		t.Fatalf("error should be reported as forbidden, got %v", err)
	}
	if requests != 1 {
		t.Fatalf("a non rate limit 403 must not be retried, saw %d requests", requests)
	}
	if !strings.Contains(err.Error(), "Advanced Security") {
		t.Fatalf("error should preserve the API message, got %v", err)
	}
}

func TestNotFoundIsClassified(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNotFound)
		fmt.Fprint(writer, `{"message":"Not Found"}`)
	}))
	defer server.Close()

	err := newTestClient(server, nil).GetJSON(context.Background(), "thing", &struct{}{})
	if !IsNotFound(err) {
		t.Fatalf("error should be reported as not found, got %v", err)
	}
}

func TestServerErrorsAreRetriedThenReported(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	err := newTestClient(server, nil).GetJSON(context.Background(), "thing", &struct{}{})
	if err == nil {
		t.Fatal("expected an error after exhausting retries")
	}
	if requests < 2 {
		t.Fatalf("server errors should be retried, saw %d requests", requests)
	}
}

func TestContextCancellationStopsWork(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		fmt.Fprint(writer, `{}`)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := newTestClient(server, nil).GetJSON(ctx, "thing", &struct{}{}); err == nil {
		t.Fatal("a cancelled context must abort the request")
	}
}

func TestNextPageURL(t *testing.T) {
	link := `<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=9>; rel="last"`
	if got := nextPageURL(link); got != "https://api.github.com/x?page=2" {
		t.Errorf("nextPageURL = %q", got)
	}
	if got := nextPageURL(`<https://api.github.com/x?page=9>; rel="last"`); got != "" {
		t.Errorf("nextPageURL without a next link = %q, want empty", got)
	}
	if got := nextPageURL(""); got != "" {
		t.Errorf("nextPageURL of empty header = %q, want empty", got)
	}
}

func TestRestPrefixHandlesEnterpriseHosts(t *testing.T) {
	cases := map[string]string{
		"github.com":      "https://api.github.com/",
		"ghe.example.com": "https://ghe.example.com/api/v3/",
		"tenant.ghe.com":  "https://api.tenant.ghe.com/",
	}
	for host, want := range cases {
		if got := restPrefix(host); got != want {
			t.Errorf("restPrefix(%q) = %q, want %q", host, got, want)
		}
	}
}

// decodeJSON keeps the pagination test readable.
func decodeJSON(data []byte, out any) error {
	return json.Unmarshal(data, out)
}
