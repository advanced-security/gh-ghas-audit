package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"
)

const (
	// defaultRateLimitWaitSeconds is the fallback wait duration when no rate limit reset header is provided
	defaultRateLimitWaitSeconds = 60
	// rateLimitResetBuffer is added to the calculated wait duration to ensure the rate limit has reset
	rateLimitResetBuffer = 1 * time.Second
)

// LANGUAGE_MAPPING normalizes different language names into a standard set.
var LANGUAGE_MAPPING = map[string]string{
	"actions":               "actions",
	"csharp":                "csharp",
	"c#":                    "csharp",
	"c-cpp":                 "c-cpp",
	"cpp":                   "c-cpp",
	"c":                     "c-cpp",
	"c++":                   "c-cpp",
	"go":                    "go",
	"java-kotlin":           "java-kotlin",
	"java":                  "java-kotlin",
	"javascript-typescript": "javascript-typescript",
	"javascript":            "javascript-typescript",
	"typescript":            "typescript",
	"python":                "python",
	"ruby":                  "ruby",
	"kotlin":                "java-kotlin",
	"swift":                 "swift",
}

// LanguageCoverage is the struct for the GitHub /languages API response.
type LanguageCoverage map[string]int

// DefaultSetupConfig is the response structure from code-scanning/default-setup.
type DefaultSetupConfig struct {
	State      string
	Languages  []string
	QuerySuite string
	UpdatedAt  string
	Scheduled  string
}

// normalizeLanguages returns a list of normalized languages matching LANGUAGE_MAPPING.
func NormalizeLanguages(langMap LanguageCoverage) []string {
	seen := make(map[string]bool)
	var result []string
	for k := range langMap {
		mapped, ok := LANGUAGE_MAPPING[strings.ToLower(k)]
		if !ok {
			continue
		}
		if !seen[mapped] {
			seen[mapped] = true
			result = append(result, mapped)
		}
	}
	return result
}

// parseRepository extracts the "org" and "repo" parts from "owner/repo".
func ParseRepository(repoString string) (string, string) {
	parts := strings.SplitN(repoString, "/", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

// listOrgs returns a list of organization names for the authenticated user.
func ListOrgs(client *api.RESTClient) ([]string, error) {
	response := []struct{ Login string }{}
	err := client.Get("user/orgs", &response)
	if err != nil {
		return nil, err
	}
	orgs := make([]string, len(response))
	for i, org := range response {
		orgs[i] = org.Login
	}
	return orgs, nil
}

// makeRequestWithRetry executes an API request with rate limit handling and retries.
// Returns the response or an error after exhausting retries.
func makeRequestWithRetry(client *api.RESTClient, method string, path string, body io.Reader) (*http.Response, error) {
	maxRetries := 5

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			fmt.Printf("Retry attempt %d/%d for request...\n", attempt, maxRetries)
		}
		resp, err := client.Request(method, path, body)

		// Check if error is due to rate limiting
		if err != nil {
			// Try to cast to HTTPError to check for rate limit
			if httpErr, ok := err.(*api.HTTPError); ok {
				if httpErr.StatusCode == 403 || httpErr.StatusCode == 429 {
					// Handle rate limiting from error
					if handleRateLimitFromError(httpErr) {
						if attempt >= maxRetries {
							return nil, fmt.Errorf("exceeded maximum retries due to rate limiting")
						}
						fmt.Printf("Rate limit handled, will retry (attempt %d/%d)\n", attempt+1, maxRetries)
						continue
					}
				}
			}
			return nil, fmt.Errorf("request failed: %w", err)
		}

		// Success - return response for caller to handle
		return resp, nil
	}

	return nil, fmt.Errorf("failed to get response after retries")
}

// listRepos returns a list of repository names under a given org.
func ListRepos(client *api.RESTClient, org string) ([]string, error) {
	perPage := 100
	var repos []string
	path := fmt.Sprintf("orgs/%s/repos?per_page=%d", org, perPage)

	for path != "" {
		response, err := makeRequestWithRetry(client, "GET", path, nil)
		if err != nil {
			return nil, err
		}

		if response.StatusCode != 200 {
			response.Body.Close()
			return nil, fmt.Errorf("unexpected status code: %d", response.StatusCode)
		}

		var repoList []struct {
			Name     string
			Archived bool
			Fork     bool
		}

		// Decode response body
		if err := json.NewDecoder(response.Body).Decode(&repoList); err != nil {
			response.Body.Close()
			return nil, err
		}

		for _, repo := range repoList {
			if SkipArchived && repo.Archived {
				continue
			}
			if SkipForks && repo.Fork {
				continue
			}
			repos = append(repos, repo.Name)
		}

		// Check for next page in Link header before closing body
		nextPath := ""
		if linkHeader := response.Header.Get("Link"); linkHeader != "" {
			nextPath = extractNextURL(linkHeader)
		}

		// Close the response body before next iteration
		response.Body.Close()

		// Set path for next iteration
		path = nextPath
	}

	return repos, nil
}

// extractNextURL parses the Link header and returns the URL for rel="next"
func extractNextURL(linkHeader string) string {
	// Link header format: <url>; rel="next", <url>; rel="last", etc.
	links := strings.Split(linkHeader, ",")
	for _, link := range links {
		parts := strings.Split(strings.TrimSpace(link), ";")
		if len(parts) < 2 {
			continue
		}
		// Check if this is the "next" link
		if strings.Contains(parts[1], `rel="next"`) {
			// Extract URL from <url>
			url := strings.TrimSpace(parts[0])
			url = strings.TrimPrefix(url, "<")
			url = strings.TrimSuffix(url, ">")
			return url
		}
	}
	return ""
}

// handleRateLimitFromError checks HTTPError for rate limiting and waits if necessary.
// Returns true if the request should be retried, false otherwise.
func handleRateLimitFromError(httpErr *api.HTTPError) bool {
	if httpErr.StatusCode != 403 && httpErr.StatusCode != 429 {
		return false
	}

	// Check if this is a rate limit error by looking for rate limit headers
	remainingHeader := httpErr.Headers.Get("X-RateLimit-Remaining")
	retryAfterHeader := httpErr.Headers.Get("Retry-After")
	resetHeader := httpErr.Headers.Get("X-RateLimit-Reset")

	// Primary rate limit: 403/429 with x-ratelimit-remaining: 0
	if remainingHeader == "0" {
		fmt.Printf("Primary rate limit exceeded. Status: %d, Remaining: %s\n",
			httpErr.StatusCode, remainingHeader)
		if resetHeader != "" {
			if resetUnix, err := strconv.ParseInt(resetHeader, 10, 64); err == nil {
				resetAt := time.Unix(resetUnix, 0)
				now := time.Now()
				waitDuration := time.Until(resetAt) + rateLimitResetBuffer
				fmt.Printf("Rate limit reset at: %s, Current time: %s, Wait duration: %.0f seconds\n",
					resetAt.Format("15:04:05"), now.Format("15:04:05"), waitDuration.Seconds())
				if waitDuration > 0 {
					fmt.Printf("Waiting %.0f seconds...\n", waitDuration.Seconds())
					time.Sleep(waitDuration)
					fmt.Println("Wait complete, retrying request...")
					return true
				} else {
					fmt.Println("Wait duration is negative or zero, rate limit should already be reset")
					return true
				}
			}
		}
		// If no reset header, wait a default amount
		fmt.Printf("No X-RateLimit-Reset header found, waiting %d seconds...\n", defaultRateLimitWaitSeconds)
		time.Sleep(defaultRateLimitWaitSeconds * time.Second)
		return true
	}

	// Secondary rate limit: check for retry-after header
	if retryAfterHeader != "" {
		fmt.Printf("Secondary rate limit exceeded. Status: %d, Retry-After: %s seconds\n",
			httpErr.StatusCode, retryAfterHeader)
		if seconds, err := strconv.Atoi(retryAfterHeader); err == nil {
			fmt.Printf("Waiting %d seconds...\n", seconds)
			time.Sleep(time.Duration(seconds) * time.Second)
			return true
		}
	}

	// Not a rate limit error - it's a legitimate 403/429 for other reasons
	return false
}

// getDefaultSetup fetches the default setup configuration for a repository.
func GetDefaultSetup(client *api.RESTClient, org string, repo string) (DefaultSetupConfig, error) {
	response := DefaultSetupConfig{}
	path := fmt.Sprintf("repos/%s/%s/code-scanning/default-setup", org, repo)

	resp, err := makeRequestWithRetry(client, "GET", path, nil)
	if err != nil {
		return response, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return response, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return response, fmt.Errorf("failed to decode response: %w", err)
	}

	return response, nil
}

// Languages returns a list of keys in the LanguageCoverage map.
func (l LanguageCoverage) Languages() []string {
	var keys []string
	for k := range l {
		keys = append(keys, k)
	}
	return keys
}

// getLanguages fetches a repository's language breakdown.
func GetLanguages(client *api.RESTClient, org string, repo string) (LanguageCoverage, error) {
	response := make(LanguageCoverage)
	path := fmt.Sprintf("repos/%s/%s/languages", org, repo)

	resp, err := makeRequestWithRetry(client, "GET", path, nil)
	if err != nil {
		return response, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return response, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return response, fmt.Errorf("failed to decode response: %w", err)
	}

	return response, nil
}

// ArrayDiff returns elements in 'a' that are not in 'b'.
func ArrayDiff[K comparable](a []K, b []K) []K {
	m := make(map[K]bool)
	for _, item := range b {
		m[item] = true
	}
	var diff []K
	for _, item := range a {
		if _, ok := m[item]; !ok {
			diff = append(diff, item)
		}
	}
	return diff
}
