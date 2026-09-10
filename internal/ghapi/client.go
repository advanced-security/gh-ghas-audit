// Package ghapi provides the HTTP layer used to collect code scanning status:
// a REST client with conditional requests, rate limit handling and request
// accounting, plus a thin GraphQL wrapper used for cheap bulk enumeration.
package ghapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/cli/go-gh/v2/pkg/auth"
)

const (
	// maxAttempts bounds retries for a single request.
	maxAttempts = 5
	// maxRateLimitWait caps how long a single request will block waiting for a
	// primary rate limit reset, so a scan cannot hang indefinitely.
	maxRateLimitWait = 15 * time.Minute
	acceptJSON       = "application/vnd.github+json"
	apiVersionHeader = "X-GitHub-Api-Version"
	apiVersion       = "2022-11-28"
)

// defaultSecondaryWait is used when a rate limit response carries no usable
// timing header. GitHub's guidance for that case is to wait at least a minute.
// It is a variable so tests can shorten the schedule.
var defaultSecondaryWait = 60 * time.Second

// ResponseCache stores conditional-request state between runs. Implemented by
// internal/cache; declared here as an interface to keep the dependency
// one-directional.
type ResponseCache interface {
	Get(key string) (etag string, body []byte, next string, ok bool)
	Put(key string, etag string, body []byte, next string)
}

// ErrResponseTooLarge is returned when a size-limited request produced a body
// bigger than the caller's remaining budget. Callers treat it as the budget
// being spent rather than as a fault in the repository.
var ErrResponseTooLarge = errors.New("response exceeded the configured size limit")

// StatusError is returned for non-successful HTTP responses.
type StatusError struct {
	StatusCode int
	Message    string
	URL        string
	// RateLimited marks a response that was a rate limit rather than a
	// permission or licensing problem. The distinction matters because a
	// permission error is a durable fact about a repository, while a rate
	// limit is a transient condition that must never be reported as a
	// repository's health.
	RateLimited bool
}

func (e *StatusError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("%s: HTTP %d", e.URL, e.StatusCode)
	}
	return fmt.Sprintf("%s: HTTP %d: %s", e.URL, e.StatusCode, e.Message)
}

// IsNotFound reports whether an error is an HTTP 404. For code scanning
// endpoints this usually means the feature is not enabled for the repository
// rather than that the repository is missing.
func IsNotFound(err error) bool {
	return hasStatus(err, http.StatusNotFound)
}

// IsForbidden reports whether an error is an HTTP 403 that is not a rate
// limit, which for these endpoints normally indicates a licensing or
// permission problem.
func IsForbidden(err error) bool {
	return hasStatus(err, http.StatusForbidden) && !IsRateLimited(err)
}

// IsRateLimited reports whether an error was caused by a primary or secondary
// rate limit that outlasted the retry budget.
func IsRateLimited(err error) bool {
	var statusErr *StatusError
	if errors.As(err, &statusErr) {
		return statusErr.RateLimited
	}
	return false
}

func hasStatus(err error, code int) bool {
	var statusErr *StatusError
	if errors.As(err, &statusErr) {
		return statusErr.StatusCode == code
	}
	return false
}

// Stats accumulates request accounting across concurrent workers.
type Stats struct {
	RESTRequests    atomic.Int64
	GraphQLRequests atomic.Int64
	CacheHits       atomic.Int64
	RateLimitWaits  atomic.Int64
	rateRemaining   atomic.Int64
}

// RateLimitRemaining returns the most recently observed remaining quota.
func (s *Stats) RateLimitRemaining() int {
	return int(s.rateRemaining.Load())
}

// Client performs authenticated GitHub API calls.
type Client struct {
	http      *http.Client
	graphql   *api.GraphQLClient
	host      string
	restBase  string
	cache     ResponseCache
	stats     *Stats
	semaphore chan struct{}

	// warnOnce prevents repeating the same host-level warning for every
	// repository in a large scan.
	warnOnce sync.Map
}

// Options configures a Client.
type Options struct {
	// Host overrides the GitHub host. Empty uses the gh CLI default.
	Host string
	// Cache enables conditional requests. May be nil.
	Cache ResponseCache
	// Concurrency bounds simultaneous in-flight requests. GitHub documents a
	// hard ceiling of 100 concurrent requests; staying well below it is what
	// keeps large scans clear of secondary rate limits.
	Concurrency int
	// Timeout bounds a single HTTP request.
	Timeout time.Duration
}

// NewClient builds a Client using gh CLI authentication.
func NewClient(opts Options) (*Client, error) {
	host := opts.Host
	if host == "" {
		host, _ = auth.DefaultHost()
	}
	if host == "" {
		return nil, errors.New("unable to determine GitHub host; run `gh auth login` or set GH_HOST")
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	httpClient, err := api.NewHTTPClient(api.ClientOptions{
		Host:    host,
		Timeout: timeout,
		Headers: map[string]string{
			"Accept":         acceptJSON,
			apiVersionHeader: apiVersion,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("creating HTTP client: %w", err)
	}

	graphqlClient, err := api.NewGraphQLClient(api.ClientOptions{
		Host:    host,
		Timeout: timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("creating GraphQL client: %w", err)
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 8
	}

	return &Client{
		http:      httpClient,
		graphql:   graphqlClient,
		host:      host,
		restBase:  restPrefix(host),
		cache:     opts.Cache,
		stats:     &Stats{},
		semaphore: make(chan struct{}, concurrency),
	}, nil
}

// Host returns the GitHub host in use.
func (c *Client) Host() string { return c.host }

// Stats exposes request accounting.
func (c *Client) Stats() *Stats { return c.stats }

// IsEnterpriseServer reports whether the target is GitHub Enterprise Server,
// where some organization-level endpoints may not exist.
func (c *Client) IsEnterpriseServer() bool {
	return auth.IsEnterprise(c.host) && !auth.IsTenancy(c.host)
}

// restPrefix mirrors go-gh's REST base URL resolution, including Enterprise
// Server and tenanted (ghe.com) hosts.
func restPrefix(hostname string) string {
	normalized := auth.NormalizeHostname(hostname)
	if auth.IsEnterprise(normalized) && !auth.IsTenancy(normalized) {
		return fmt.Sprintf("https://%s/api/v3/", normalized)
	}
	if strings.EqualFold(normalized, "github.localhost") {
		return fmt.Sprintf("http://api.%s/", normalized)
	}
	return fmt.Sprintf("https://api.%s/", normalized)
}

// resolveURL turns a relative API path into an absolute URL.
func (c *Client) resolveURL(pathOrURL string) string {
	if strings.HasPrefix(pathOrURL, "http://") || strings.HasPrefix(pathOrURL, "https://") {
		return pathOrURL
	}
	return c.restBase + strings.TrimPrefix(pathOrURL, "/")
}

// GetJSON performs a GET and decodes the JSON body into out.
// It uses stored ETags to issue conditional requests; a 304 response is served
// from cache and does not count against the primary rate limit.
func (c *Client) GetJSON(ctx context.Context, path string, out any) error {
	body, _, err := c.get(ctx, path, true, 0)
	if err != nil {
		return err
	}
	if out == nil || len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decoding response from %s: %w", path, err)
	}
	return nil
}

// GetBytes performs a GET and returns the raw response body. It is used for
// non-JSON endpoints such as the Actions log archive, which responds with a
// redirect to a signed download URL.
//
// These responses bypass the cache: log archives are multi-megabyte binaries
// that would dominate cache size for no benefit, since they are only ever read
// once per run.
func (c *Client) GetBytes(ctx context.Context, path string) ([]byte, error) {
	body, _, err := c.get(ctx, path, false, 0)
	return body, err
}

// GetBytesLimited is GetBytes with a hard cap on the response size. It exists
// so an unbounded download, such as an Actions log archive, cannot overshoot a
// caller's byte budget in a single request.
func (c *Client) GetBytesLimited(ctx context.Context, path string, limit int64) ([]byte, error) {
	body, _, err := c.get(ctx, path, false, limit)
	return body, err
}

// GetPaginatedJSON walks every page of a list endpoint, invoking collect with
// each page body. Collect should append decoded items to its own slice.
func (c *Client) GetPaginatedJSON(ctx context.Context, path string, collect func(page []byte) error) error {
	next := path
	for next != "" {
		body, link, err := c.get(ctx, next, true, 0)
		if err != nil {
			return err
		}
		if len(body) > 0 {
			if err := collect(body); err != nil {
				return err
			}
		}
		next = link
	}
	return nil
}

// get executes a conditional GET with retries and returns the body plus the
// URL of the next page, if any.
func (c *Client) get(ctx context.Context, pathOrURL string, useCache bool, limit int64) ([]byte, string, error) {
	target := c.resolveURL(pathOrURL)

	var cachedETag string
	var cachedBody []byte
	var cachedNext string
	if useCache && c.cache != nil {
		if etag, body, storedNext, ok := c.cache.Get(target); ok {
			cachedETag = etag
			cachedBody = body
			cachedNext = storedNext
		}
	}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := c.acquire(ctx); err != nil {
			return nil, "", err
		}
		body, next, status, headers, err := c.do(ctx, target, cachedETag, limit)
		c.release()

		if err != nil {
			lastErr = err
			// Network-level failures are worth one bounded retry.
			if attempt+1 < maxAttempts && isRetryableTransport(err) {
				if waitErr := sleepCtx(ctx, backoff(attempt)); waitErr != nil {
					return nil, "", waitErr
				}
				continue
			}
			return nil, "", err
		}

		switch {
		case status == http.StatusNotModified:
			c.stats.CacheHits.Add(1)
			// A 304 is not obliged to repeat the Link header. Falling back to
			// the stored next page URL is what stops a revalidated first page
			// from looking like the only page.
			if next == "" {
				next = cachedNext
			}
			return cachedBody, next, nil

		case status >= 200 && status < 300:
			if useCache && c.cache != nil {
				if etag := headers.Get("ETag"); etag != "" {
					c.cache.Put(target, etag, body, next)
				}
			}
			return body, next, nil

		case status == http.StatusForbidden || status == http.StatusTooManyRequests:
			wait, isRateLimit := rateLimitDelay(headers, body)
			if !isRateLimit {
				return nil, "", newStatusError(status, body, target, false)
			}
			if attempt+1 >= maxAttempts {
				// Report this as a rate limit rather than a permission
				// problem, so callers never record it as a repository's
				// health.
				return nil, "", newStatusError(status, body, target, true)
			}
			c.stats.RateLimitWaits.Add(1)
			if err := sleepCtx(ctx, wait); err != nil {
				return nil, "", err
			}
			continue

		case status >= 500:
			if attempt+1 >= maxAttempts {
				return nil, "", newStatusError(status, body, target, false)
			}
			if err := sleepCtx(ctx, backoff(attempt)); err != nil {
				return nil, "", err
			}
			continue

		default:
			return nil, "", newStatusError(status, body, target, false)
		}
	}

	if lastErr != nil {
		return nil, "", lastErr
	}
	return nil, "", fmt.Errorf("request to %s failed after %d attempts", target, maxAttempts)
}

func (c *Client) do(ctx context.Context, target, etag string, limit int64) ([]byte, string, int, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, "", 0, nil, err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	c.stats.RESTRequests.Add(1)
	if remaining := resp.Header.Get("X-RateLimit-Remaining"); remaining != "" {
		if value, convErr := strconv.ParseInt(remaining, 10, 64); convErr == nil {
			c.stats.rateRemaining.Store(value)
		}
	}

	reader := io.Reader(resp.Body)
	if limit > 0 {
		// One extra byte distinguishes "exactly at the limit" from
		// "truncated", so an oversized archive can be reported rather than
		// silently analyzed as if it were complete.
		reader = io.LimitReader(resp.Body, limit+1)
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, "", resp.StatusCode, resp.Header, err
	}
	if limit > 0 && int64(len(body)) > limit {
		return nil, "", resp.StatusCode, resp.Header,
			fmt.Errorf("%w: response from %s exceeded %d bytes", ErrResponseTooLarge, target, limit)
	}

	return body, nextPageURL(resp.Header.Get("Link")), resp.StatusCode, resp.Header, nil
}

func (c *Client) acquire(ctx context.Context) error {
	select {
	case c.semaphore <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) release() { <-c.semaphore }

// GraphQL executes a GraphQL query and decodes the response into out.
func (c *Client) GraphQL(ctx context.Context, query string, variables map[string]any, out any) error {
	if err := c.acquire(ctx); err != nil {
		return err
	}
	defer c.release()

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		c.stats.GraphQLRequests.Add(1)
		err := c.graphql.DoWithContext(ctx, query, variables, out)
		if err == nil {
			return nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !isRetryableTransport(err) {
			return err
		}
		if waitErr := sleepCtx(ctx, backoff(attempt)); waitErr != nil {
			return waitErr
		}
	}
	return lastErr
}

// WarnOnce reports whether a warning key has already been emitted, so that a
// host-wide limitation is reported once rather than per repository.
func (c *Client) WarnOnce(key string) bool {
	_, loaded := c.warnOnce.LoadOrStore(key, true)
	return !loaded
}

func newStatusError(status int, body []byte, target string, rateLimited bool) error {
	message := ""
	var payload struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &payload); err == nil {
		message = payload.Message
	}
	if message == "" && len(body) > 0 && len(body) < 200 {
		message = strings.TrimSpace(string(bytes.TrimSpace(body)))
	}
	return &StatusError{StatusCode: status, Message: message, URL: target, RateLimited: rateLimited}
}

// secondaryLimitPattern matches the body GitHub returns for secondary rate
// limits, which are not always accompanied by Retry-After or an exhausted
// X-RateLimit-Remaining header.
var secondaryLimitPattern = regexp.MustCompile(`(?i)(secondary rate limit|abuse detection|rate limit exceeded|too many requests)`)

// rateLimitDelay inspects a response to distinguish a genuine rate limit from
// an ordinary 403, and returns how long to wait before retrying.
//
// Getting this wrong is costly in both directions: treating a licensing 403 as
// a rate limit would stall a scan, while treating a rate limit as a permission
// error would report healthy repositories as unreadable.
func rateLimitDelay(headers http.Header, body []byte) (time.Duration, bool) {
	if retryAfter := headers.Get("Retry-After"); retryAfter != "" {
		if seconds, err := strconv.Atoi(retryAfter); err == nil {
			return clampWait(time.Duration(seconds) * time.Second), true
		}
	}

	if headers.Get("X-RateLimit-Remaining") == "0" {
		if reset := headers.Get("X-RateLimit-Reset"); reset != "" {
			if resetUnix, err := strconv.ParseInt(reset, 10, 64); err == nil {
				return clampWait(time.Until(time.Unix(resetUnix, 0)) + time.Second), true
			}
		}
		return defaultSecondaryWait, true
	}

	// Secondary rate limits can arrive with neither header set, in which case
	// the response body is the only signal. GitHub's guidance for that case is
	// to wait at least one minute before retrying.
	if len(body) > 0 && secondaryLimitPattern.Match(body) {
		return defaultSecondaryWait, true
	}

	return 0, false
}

func clampWait(wait time.Duration) time.Duration {
	if wait <= 0 {
		return time.Second
	}
	if wait > maxRateLimitWait {
		return maxRateLimitWait
	}
	return wait
}

// backoffBase is the first retry delay. It is a variable so tests can shorten
// the retry schedule without changing production behaviour.
var backoffBase = 500 * time.Millisecond

// backoff returns an exponential delay with jitter to avoid synchronized
// retries across concurrent workers.
func backoff(attempt int) time.Duration {
	base := time.Duration(math.Pow(2, float64(attempt))) * backoffBase
	if base > 30*time.Second {
		base = 30 * time.Second
	}
	if base <= 0 {
		return 0
	}
	jitter := time.Duration(rand.Int63n(int64(base/2 + 1)))
	return base + jitter
}

func sleepCtx(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func isRetryableTransport(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, hint := range []string{"connection reset", "eof", "timeout", "temporary", "no such host", "broken pipe"} {
		if strings.Contains(message, hint) {
			return true
		}
	}
	return false
}

// nextPageURL extracts the rel="next" URL from a Link header.
func nextPageURL(link string) string {
	if link == "" {
		return ""
	}
	for _, segment := range strings.Split(link, ",") {
		parts := strings.Split(strings.TrimSpace(segment), ";")
		if len(parts) < 2 {
			continue
		}
		isNext := false
		for _, part := range parts[1:] {
			if strings.Contains(part, `rel="next"`) {
				isNext = true
				break
			}
		}
		if !isNext {
			continue
		}
		raw := strings.TrimSpace(parts[0])
		raw = strings.TrimPrefix(raw, "<")
		raw = strings.TrimSuffix(raw, ">")
		if _, err := url.Parse(raw); err != nil {
			return ""
		}
		return raw
	}
	return ""
}
