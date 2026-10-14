package ghapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"
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

// redirectTransport rewrites every outgoing request to target a local test
// server, regardless of the host api.NewGraphQLClient resolved for it. This
// lets tests exercise the real go-gh GraphQL client end to end without a `gh
// auth login` in the test environment.
type redirectTransport struct {
	target *url.URL
}

func (t *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	redirected := req.Clone(req.Context())
	redirected.URL.Scheme = t.target.Scheme
	redirected.URL.Host = t.target.Host
	redirected.Host = t.target.Host
	return http.DefaultTransport.RoundTrip(redirected)
}

// newTestGraphQLClient builds a Client whose GraphQL requests are redirected
// to a local test server.
func newTestGraphQLClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parsing test server URL: %v", err)
	}
	graphqlClient, err := api.NewGraphQLClient(api.ClientOptions{
		Host:      "github.com",
		AuthToken: "test-token",
		Transport: &redirectTransport{target: target},
	})
	if err != nil {
		t.Fatalf("creating test GraphQL client: %v", err)
	}
	return &Client{
		graphql:   graphqlClient,
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

// The GraphQL transport surfaces non-2xx responses as *api.HTTPError rather
// than the *StatusError the REST path uses, so a secondary rate limit must be
// recognized from that type too or the GraphQL query fails on its first hit
// instead of being retried like an equivalent REST call.
func TestGraphQLSecondaryRateLimitIsRetried(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		if requests == 1 {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusForbidden)
			fmt.Fprint(writer, `{"message":"You have exceeded a secondary rate limit. Please wait a few minutes before you try again."}`)
			return
		}
		fmt.Fprint(writer, `{"data":{"repository":{"name":"ok"}}}`)
	}))
	defer server.Close()

	client := newTestGraphQLClient(t, server)

	var response struct {
		Repository struct {
			Name string
		}
	}
	if err := client.GraphQL(context.Background(), "query{repository{name}}", nil, &response); err != nil {
		t.Fatalf("a secondary rate limit should be retried: %v", err)
	}
	if response.Repository.Name != "ok" || requests != 2 {
		t.Fatalf("name = %q after %d requests", response.Repository.Name, requests)
	}
	if client.Stats().RateLimitWaits.Load() != 1 {
		t.Fatalf("rate limit waits = %d, want 1", client.Stats().RateLimitWaits.Load())
	}
}

// Once the retry budget is exhausted, a GraphQL rate limit must be
// identifiable as such so callers never record it as a repository's health,
// the same guarantee the REST path already provides.
func TestGraphQLExhaustedRateLimitIsReportedAsRateLimited(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusForbidden)
		fmt.Fprint(writer, `{"message":"You have exceeded a secondary rate limit"}`)
	}))
	defer server.Close()

	client := newTestGraphQLClient(t, server)

	err := client.GraphQL(context.Background(), "query{repository{name}}", nil, &struct{}{})
	if err == nil {
		t.Fatal("expected an error after exhausting retries")
	}
	if !IsRateLimited(err) {
		t.Fatalf("error should be identifiable as a rate limit, got %v", err)
	}
}

// GitHub's GraphQL endpoint can return a 502/503/504 when its own
// infrastructure falters; this is unrelated to rate limiting and unrelated
// to the query itself, so it must be retried rather than reported as a
// permanent failure on the first occurrence.
func TestGraphQLBadGatewayIsRetried(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		if requests == 1 {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusBadGateway)
			fmt.Fprint(writer, `{"message":"502 Bad Gateway"}`)
			return
		}
		fmt.Fprint(writer, `{"data":{"repository":{"name":"ok"}}}`)
	}))
	defer server.Close()

	client := newTestGraphQLClient(t, server)

	var response struct {
		Repository struct {
			Name string
		}
	}
	if err := client.GraphQL(context.Background(), "query{repository{name}}", nil, &response); err != nil {
		t.Fatalf("a 502 should be retried: %v", err)
	}
	if response.Repository.Name != "ok" || requests != 2 {
		t.Fatalf("name = %q after %d requests", response.Repository.Name, requests)
	}
}

// GitHub's GraphQL engine can report a field-level execution timeout (an
// application-level error in the response body's "errors" array, distinct
// from any HTTP status code or transport failure) for expensive fields such
// as dependencyGraphManifests. This is ordinarily transient load, not a
// permanently broken query, so it must be retried.
func TestGraphQLFieldTimeoutIsRetried(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writer.Header().Set("Content-Type", "application/json")
		if requests == 1 {
			fmt.Fprint(writer, `{"data":null,"errors":[{"message":"timedout","path":["repository","dependencyGraphManifests"]}]}`)
			return
		}
		fmt.Fprint(writer, `{"data":{"repository":{"name":"ok"}}}`)
	}))
	defer server.Close()

	client := newTestGraphQLClient(t, server)

	var response struct {
		Repository struct {
			Name string
		}
	}
	if err := client.GraphQL(context.Background(), "query{repository{name}}", nil, &response); err != nil {
		t.Fatalf("a field execution timeout should be retried: %v", err)
	}
	if response.Repository.Name != "ok" || requests != 2 {
		t.Fatalf("name = %q after %d requests", response.Repository.Name, requests)
	}
}

// A genuine query problem (an invalid field, a bad argument, and so on) fails
// identically on every attempt; it must not be masked behind a retry loop
// just because it is a GraphQL response-level error.
func TestGraphQLNonTransientErrorIsNotRetried(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprint(writer, `{"data":null,"errors":[{"message":"Field 'bogus' doesn't exist on type 'Repository'","path":["repository","bogus"]}]}`)
	}))
	defer server.Close()

	client := newTestGraphQLClient(t, server)

	err := client.GraphQL(context.Background(), "query{repository{bogus}}", nil, &struct{}{})
	if err == nil {
		t.Fatal("expected an error for an invalid query field")
	}
	if requests != 1 {
		t.Fatalf("a non-transient GraphQL error must not be retried, got %d requests", requests)
	}
}

// A 200 response whose body is empty or truncated (for example a connection
// cut mid-transfer after the status line was already sent) fails
// json.Unmarshal with Go's "unexpected end of JSON input" error. This is a
// read-completeness failure of the HTTP layer, not a problem with the query,
// and looks identical to a genuine transport error on retry; it must be
// retried rather than reported as a permanent failure on the first
// occurrence, exactly like a connection reset or timeout would be.
func TestGraphQLTruncatedResponseBodyIsRetried(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writer.Header().Set("Content-Type", "application/json")
		if requests == 1 {
			// An empty body with a 200 status reproduces exactly the
			// "unexpected end of JSON input" error json.Unmarshal returns
			// for a truncated response.
			return
		}
		fmt.Fprint(writer, `{"data":{"repository":{"name":"ok"}}}`)
	}))
	defer server.Close()

	client := newTestGraphQLClient(t, server)

	var response struct {
		Repository struct {
			Name string
		}
	}
	if err := client.GraphQL(context.Background(), "query{repository{name}}", nil, &response); err != nil {
		t.Fatalf("a truncated response body should be retried: %v", err)
	}
	if response.Repository.Name != "ok" || requests != 2 {
		t.Fatalf("name = %q after %d requests", response.Repository.Name, requests)
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
	entries map[string][3]string
}

func newMemoryCache() *memoryCache {
	return &memoryCache{entries: map[string][3]string{}}
}

func (m *memoryCache) Get(key string) (string, []byte, string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.entries[key]
	if !ok {
		return "", nil, "", false
	}
	return entry[0], []byte(entry[1]), entry[2], true
}

func (m *memoryCache) Put(key string, etag string, body []byte, next string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[key] = [3]string{etag, string(body), next}
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

// GetBytesLimited and GetSARIFLimited are used with math.MaxInt64 to mean
// "unlimited" (the CLI's --deep-diagnostics-max-mb/-max-sarif-mb 0). Adding
// one to that sentinel to build the "one extra byte" truncation check must
// not overflow into a negative limit, which io.LimitReader would treat as a
// zero-byte read and silently discard every download.
func TestUnlimitedByteBudgetDoesNotOverflowTheResponseLimiter(t *testing.T) {
	const want = "hello from an unlimited download"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(writer, want)
	}))
	defer server.Close()

	body, err := newTestClient(server, nil).GetBytesLimited(context.Background(), "thing", math.MaxInt64)
	if err != nil {
		t.Fatalf("unlimited GetBytesLimited returned an error: %v", err)
	}
	if string(body) != want {
		t.Fatalf("GetBytesLimited(math.MaxInt64) = %q, want %q", body, want)
	}
}

// A finite limit must still behave: a response under the cap is returned in
// full, and a response over the cap is reported rather than truncated.
func TestFiniteByteBudgetStillEnforcesTheLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(writer, "0123456789")
	}))
	defer server.Close()
	client := newTestClient(server, nil)

	body, err := client.GetBytesLimited(context.Background(), "thing", 10)
	if err != nil {
		t.Fatalf("response at exactly the limit should succeed: %v", err)
	}
	if string(body) != "0123456789" {
		t.Fatalf("GetBytesLimited(10) = %q, want the full 10 byte body", body)
	}

	if _, err := client.GetBytesLimited(context.Background(), "thing", 5); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("response over the limit should be reported as too large, got %v", err)
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
