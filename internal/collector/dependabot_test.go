package collector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/ghapi"
	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
)

// dependabotFakeClient serves canned responses so the Dependabot collector
// can be exercised without network access. It is a separate type from
// collector_test.go's fakeClient (rather than a shared/reused one) because it
// must treat a nil `out` parameter to GetJSON as "successful, nothing to
// decode" to mirror the real ghapi.Client's 204-response behavior, which the
// vulnerability-alerts enablement check on this collector depends on and
// which no existing code scanning call site exercises.
type dependabotFakeClient struct {
	responses map[string]any
	graphql   func(query string, variables map[string]any, out any) error
	stats     ghapi.Stats

	// securityUpdatePRNumbers and securityUpdatePRsErr configure the default
	// vulnerabilityAlerts GraphQL response baseRepoResponses installs.
	// Individual tests set these before calling Collect to simulate a
	// repository with Dependabot security update pull requests, or a query
	// that could not be evaluated (nil map fallback path).
	securityUpdatePRNumbers map[int]bool
	securityUpdatePRsErr    error
	// securityUpdateStalePackages simulates alerts whose dependabotUpdate
	// link is absent or points at a closed pull request (see
	// securityUpdateEvidence.vulnerablePackages): each entry becomes an
	// AUTO_DISMISSED alert node with no live pull request link.
	securityUpdateStalePackages map[string]bool

	mu     sync.Mutex
	warned map[string]bool
}

func newDependabotFakeClient() *dependabotFakeClient {
	return &dependabotFakeClient{
		responses:                   map[string]any{},
		warned:                      map[string]bool{},
		securityUpdatePRNumbers:     map[int]bool{},
		securityUpdateStalePackages: map[string]bool{},
	}
}

func (f *dependabotFakeClient) Host() string        { return "github.com" }
func (f *dependabotFakeClient) Stats() *ghapi.Stats { return &f.stats }
func (f *dependabotFakeClient) WarnOnce(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.warned[key] {
		return false
	}
	f.warned[key] = true
	return true
}

// set registers a response for any request whose path starts with prefix.
// The longest matching prefix wins, so a general and a specific path can
// coexist (for example "repos/acme/repo" and
// "repos/acme/repo/contents/.github/dependabot.yml").
func (f *dependabotFakeClient) set(prefix string, value any) {
	f.responses[prefix] = value
}

func (f *dependabotFakeClient) lookup(path string) (any, bool) {
	var bestKey string
	var best any
	found := false
	for prefix, value := range f.responses {
		if strings.HasPrefix(path, prefix) && len(prefix) > len(bestKey) {
			bestKey, best, found = prefix, value, true
		}
	}
	return best, found
}

func (f *dependabotFakeClient) GetJSON(_ context.Context, path string, out any) error {
	value, ok := f.lookup(path)
	if !ok {
		return &ghapi.StatusError{StatusCode: http.StatusNotFound, URL: path, Message: "Not Found"}
	}
	if err, isErr := value.(error); isErr {
		return err
	}
	if out == nil {
		return nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(encoded, out)
}

func (f *dependabotFakeClient) GetPaginatedJSON(_ context.Context, path string, collect func([]byte) error) error {
	value, ok := f.lookup(path)
	if !ok {
		return &ghapi.StatusError{StatusCode: http.StatusNotFound, URL: path, Message: "Not Found"}
	}
	if err, isErr := value.(error); isErr {
		return err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return collect(encoded)
}

func (f *dependabotFakeClient) GraphQL(_ context.Context, query string, variables map[string]any, out any) error {
	if f.graphql == nil {
		return fmt.Errorf("unexpected GraphQL query")
	}
	return f.graphql(query, variables, out)
}

// baseRepoResponses registers the REST/GraphQL fixtures every scenario needs:
// a readable repository, a minimal npm dependabot.yml, an empty manifest set,
// enabled alerts with none open, and no open pull requests. Individual tests
// override just the pieces relevant to what they exercise.
func baseRepoResponses(t *testing.T, client *dependabotFakeClient, manifestNodes []dependencyGraphManifestNode) {
	t.Helper()

	client.set("repos/acme/repo", map[string]any{
		"name":           "repo",
		"full_name":      "acme/repo",
		"html_url":       "https://github.com/acme/repo",
		"archived":       false,
		"fork":           false,
		"visibility":     "public",
		"default_branch": "main",
		"pushed_at":      "2024-01-01T00:00:00Z",
		"security_and_analysis": map[string]any{
			"dependabot_security_updates": map[string]any{"status": "enabled"},
		},
	})

	dependabotYML := "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: \"/\"\n"
	client.set("repos/acme/repo/contents/.github/dependabot.yml", map[string]any{
		"type":    "file",
		"name":    "dependabot.yml",
		"path":    ".github/dependabot.yml",
		"content": base64.StdEncoding.EncodeToString([]byte(dependabotYML)),
	})

	client.graphql = func(query string, _ map[string]any, out any) error {
		if strings.Contains(query, "vulnerabilityAlerts") {
			response, ok := out.(*vulnerabilityAlertsPullRequestsResponse)
			if !ok {
				return fmt.Errorf("unexpected GraphQL output type %T", out)
			}
			if client.securityUpdatePRsErr != nil {
				return client.securityUpdatePRsErr
			}
			response.Repository = &struct {
				VulnerabilityAlerts struct {
					PageInfo struct {
						HasNextPage bool   `json:"hasNextPage"`
						EndCursor   string `json:"endCursor"`
					} `json:"pageInfo"`
					Nodes []vulnerabilityAlertPullRequestNode `json:"nodes"`
				} `json:"vulnerabilityAlerts"`
			}{}
			for number := range client.securityUpdatePRNumbers {
				node := vulnerabilityAlertPullRequestNode{}
				node.DependabotUpdate = &struct {
					PullRequest *struct {
						Number int    `json:"number"`
						State  string `json:"state"`
					} `json:"pullRequest"`
				}{}
				node.DependabotUpdate.PullRequest = &struct {
					Number int    `json:"number"`
					State  string `json:"state"`
				}{Number: number, State: "OPEN"}
				response.Repository.VulnerabilityAlerts.Nodes = append(response.Repository.VulnerabilityAlerts.Nodes, node)
			}
			for pkg := range client.securityUpdateStalePackages {
				node := vulnerabilityAlertPullRequestNode{State: "AUTO_DISMISSED"}
				node.SecurityVulnerability = &struct {
					Package *struct {
						Name string `json:"name"`
					} `json:"package"`
				}{}
				node.SecurityVulnerability.Package = &struct {
					Name string `json:"name"`
				}{Name: pkg}
				response.Repository.VulnerabilityAlerts.Nodes = append(response.Repository.VulnerabilityAlerts.Nodes, node)
			}
			return nil
		}

		response, ok := out.(*dependencyGraphManifestsResponse)
		if !ok {
			return fmt.Errorf("unexpected GraphQL output type %T", out)
		}
		response.Repository = &struct {
			DependencyGraphManifests struct {
				TotalCount int `json:"totalCount"`
				PageInfo   struct {
					HasNextPage bool   `json:"hasNextPage"`
					EndCursor   string `json:"endCursor"`
				} `json:"pageInfo"`
				Nodes []dependencyGraphManifestNode `json:"nodes"`
			} `json:"dependencyGraphManifests"`
		}{}
		response.Repository.DependencyGraphManifests.TotalCount = len(manifestNodes)
		response.Repository.DependencyGraphManifests.Nodes = manifestNodes
		return nil
	}

	client.set("repos/acme/repo/vulnerability-alerts", true)
	client.set("repos/acme/repo/dependabot/alerts", []dependabotAlert{})
	client.set("repos/acme/repo/pulls", []pullRequest{})
}

func directDependencyNodes(count int) []struct {
	Relationship string `json:"relationship"`
} {
	return relationshipDependencyNodes("direct", count)
}

// unknownDependencyNodes simulates a manifest GitHub could statically parse
// but not resolve at all (no lockfile, no build-time submission): every
// dependency's relationship is "unknown", not "direct". This is the actual
// shape GitHub returns for an unresolved Maven pom.xml or NuGet .csproj, as
// opposed to the "direct" relationship npm's package.json gets even without
// a lockfile.
func unknownDependencyNodes(count int) []struct {
	Relationship string `json:"relationship"`
} {
	return relationshipDependencyNodes("unknown", count)
}

func relationshipDependencyNodes(relationship string, count int) []struct {
	Relationship string `json:"relationship"`
} {
	nodes := make([]struct {
		Relationship string `json:"relationship"`
	}, count)
	for i := range nodes {
		nodes[i].Relationship = relationship
	}
	return nodes
}

// TestDependabotCollectVerboseReportsEachRepository verifies that Verbose
// emits a per-repository progress message (name and status), instead of only
// the batched "N/M repositories inspected" count.
func TestDependabotCollectVerboseReportsEachRepository(t *testing.T) {
	client := newDependabotFakeClient()
	baseRepoResponses(t, client, nil)

	var messages []string
	options := DependabotOptions{
		Repository:  "acme/repo",
		Concurrency: 1,
		Depth:       DepthHealth,
		Verbose:     true,
		Progress:    func(message string) { messages = append(messages, message) },
	}
	if _, err := NewDependabotCollector(client, options).Collect(context.Background(), "test"); err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}

	found := false
	for _, message := range messages {
		if strings.Contains(message, "acme/repo") && strings.Contains(message, "healthy") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a verbose per-repository message mentioning acme/repo and its status, got %v", messages)
	}
}

func TestDependabotCollectHealthyRepository(t *testing.T) {
	client := newDependabotFakeClient()
	baseRepoResponses(t, client, []dependencyGraphManifestNode{
		{Filename: "package-lock.json", Parseable: true, DependenciesCount: 3},
	})

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	if len(report.Repositories) != 1 {
		t.Fatalf("expected exactly one repository, got %d", len(report.Repositories))
	}
	repo := report.Repositories[0]
	if repo.Status.Overall != model.SeverityHealthy {
		t.Fatalf("overall = %q, want healthy (reasons: %v, errors: %v)", repo.Status.Overall, repo.Status.Reasons, repo.Errors)
	}
	if repo.Status.DependencyGraph != model.FeatureEnabled {
		t.Errorf("dependency graph = %q, want enabled", repo.Status.DependencyGraph)
	}
	if repo.Status.DependabotSecurityUpdates != model.FeatureEnabled {
		t.Errorf("security updates = %q, want enabled", repo.Status.DependabotSecurityUpdates)
	}
	if repo.Status.VersionUpdates != model.VersionUpdatesConfigured {
		t.Errorf("version updates = %q, want configured", repo.Status.VersionUpdates)
	}
}

// TestDependabotCollectCountsAlertsBySeverityAndClassification verifies that
// open alerts are tallied across all four severities (not just critical and
// high), and that alerts classified "malware" (a dependency that is itself
// malicious, distinct from an ordinary vulnerable dependency) are counted
// separately in OpenMalware in addition to their matching severity bucket.
func TestDependabotCollectCountsAlertsBySeverityAndClassification(t *testing.T) {
	client := newDependabotFakeClient()
	baseRepoResponses(t, client, nil)

	makeAlert := func(severity, classification string) dependabotAlert {
		alert := dependabotAlert{State: "open"}
		alert.SecurityAdvisory.Severity = severity
		alert.SecurityAdvisory.Classification = classification
		return alert
	}
	client.set("repos/acme/repo/dependabot/alerts", []dependabotAlert{
		makeAlert("critical", "general"),
		makeAlert("high", "general"),
		makeAlert("medium", "general"),
		makeAlert("low", "general"),
		makeAlert("critical", "malware"),
	})

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if repo.Alerts.OpenTotal != 5 {
		t.Errorf("open total = %d, want 5", repo.Alerts.OpenTotal)
	}
	if repo.Alerts.OpenCritical != 2 {
		t.Errorf("open critical = %d, want 2 (one general, one malware)", repo.Alerts.OpenCritical)
	}
	if repo.Alerts.OpenHigh != 1 {
		t.Errorf("open high = %d, want 1", repo.Alerts.OpenHigh)
	}
	if repo.Alerts.OpenMedium != 1 {
		t.Errorf("open medium = %d, want 1", repo.Alerts.OpenMedium)
	}
	if repo.Alerts.OpenLow != 1 {
		t.Errorf("open low = %d, want 1", repo.Alerts.OpenLow)
	}
	if repo.Alerts.OpenMalware != 1 {
		t.Errorf("open malware = %d, want 1", repo.Alerts.OpenMalware)
	}
}

func TestDependabotCollectDetectsFailingPullRequestChecks(t *testing.T) {
	client := newDependabotFakeClient()
	baseRepoResponses(t, client, nil)

	createdAt := time.Now().Add(-48 * time.Hour)
	pr := pullRequest{Number: 1, Body: "Bumps foo from 1.0.0 to 1.0.1", CreatedAt: &createdAt}
	pr.User.Login = "dependabot[bot]"
	pr.Head.SHA = "abc123"
	client.set("repos/acme/repo/pulls", []pullRequest{pr})
	client.set("repos/acme/repo/commits/abc123/status", combinedStatus{State: "failure"})

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if repo.Status.PullRequestHealth != model.PRHealthFailingChecks {
		t.Fatalf("pull request health = %q, want failing-checks", repo.Status.PullRequestHealth)
	}
	if repo.Status.Overall != model.SeverityFailing {
		t.Fatalf("overall = %q, want failing (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
	if repo.PullRequests.OpenFailingChecks != 1 {
		t.Errorf("open failing checks = %d, want 1", repo.PullRequests.OpenFailingChecks)
	}
	if repo.PullRequests.OpenVersionUpdates != 1 || repo.PullRequests.OpenSecurityUpdates != 0 {
		t.Errorf("open security/version updates = %d/%d, want 0/1", repo.PullRequests.OpenSecurityUpdates, repo.PullRequests.OpenVersionUpdates)
	}
}

// TestDependabotCollectClassifiesSecurityUpdatePullRequests verifies that a
// pull request reachable from an open vulnerability alert's
// dependabotUpdate.pullRequest field is counted as a security update, not a
// version update, even though its body contains no GHSA reference (the
// fallback heuristic would otherwise misclassify it as a version update).
func TestDependabotCollectClassifiesSecurityUpdatePullRequests(t *testing.T) {
	client := newDependabotFakeClient()
	baseRepoResponses(t, client, nil)

	securityCreatedAt := time.Now().Add(-1 * time.Hour)
	securityPR := pullRequest{Number: 7, Body: "Bumps foo from 1.0.0 to 1.0.1.\n\nYou can disable automated security fix PRs for this repo from the Security Alerts page.", CreatedAt: &securityCreatedAt}
	securityPR.User.Login = "dependabot[bot]"

	versionCreatedAt := time.Now().Add(-2 * time.Hour)
	versionPR := pullRequest{Number: 8, Body: "Bumps bar from 2.0.0 to 2.0.1.", CreatedAt: &versionCreatedAt}
	versionPR.User.Login = "dependabot[bot]"

	client.set("repos/acme/repo/pulls", []pullRequest{securityPR, versionPR})
	client.securityUpdatePRNumbers = map[int]bool{7: true}

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if repo.PullRequests.OpenSecurityUpdates != 1 {
		t.Errorf("open security updates = %d, want 1", repo.PullRequests.OpenSecurityUpdates)
	}
	if repo.PullRequests.OpenVersionUpdates != 1 {
		t.Errorf("open version updates = %d, want 1", repo.PullRequests.OpenVersionUpdates)
	}
}

// TestDependabotCollectSecurityUpdateLinkageIncludesAutoDismissedState
// verifies that the vulnerabilityAlerts query includes AUTO_DISMISSED
// alongside OPEN. GitHub can auto-dismiss an alert (for example when a
// corrected vulnerable version range makes it no longer apply) while the
// pull request Dependabot opened for it is still open and unmerged;
// filtering to only open alerts would silently misclassify that still-open
// security update as a version update. FIXED/DISMISSED alerts are excluded
// from the query, since a resolved or manually-dismissed alert is
// vanishingly unlikely to still have a currently open linked pull request,
// and excluding them at the query level bounds pagination cost for
// repositories with a large historical alert count.
func TestDependabotCollectSecurityUpdateLinkageIncludesAutoDismissedState(t *testing.T) {
	client := newDependabotFakeClient()
	baseRepoResponses(t, client, nil)

	pr := pullRequest{Number: 23, Body: "Bumps pyxdg from 0.25 to 0.26."}
	pr.User.Login = "dependabot[bot]"
	client.set("repos/acme/repo/pulls", []pullRequest{pr})

	var capturedQuery string
	fakeClient := client
	baseGraphQL := fakeClient.graphql
	fakeClient.graphql = func(query string, variables map[string]any, out any) error {
		if strings.Contains(query, "vulnerabilityAlerts") {
			capturedQuery = query
		}
		return baseGraphQL(query, variables, out)
	}

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	if _, err := NewDependabotCollector(client, options).Collect(context.Background(), "test"); err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	if !strings.Contains(capturedQuery, "states:[OPEN,AUTO_DISMISSED]") {
		t.Errorf("vulnerabilityAlerts query must filter to states:[OPEN,AUTO_DISMISSED], got: %s", capturedQuery)
	}
}

// TestDependabotCollectSecurityUpdateLinkageCapsPagination verifies that the
// vulnerabilityAlerts query stops after a bounded number of pages even when
// the server reports more pages are available. Without this cap, a
// repository with an unusually large historical alert count (real examples
// exceed 400 open/auto-dismissed alerts) forces many GraphQL round-trips per
// repository; scanning many such repositories concurrently was observed to
// measurably slow an organization-wide scan.
func TestDependabotCollectSecurityUpdateLinkageCapsPagination(t *testing.T) {
	client := newDependabotFakeClient()
	baseRepoResponses(t, client, nil)

	pr := pullRequest{Number: 1, Body: "Bumps foo from 1.0.0 to 1.0.1"}
	pr.User.Login = "dependabot[bot]"
	client.set("repos/acme/repo/pulls", []pullRequest{pr})

	var vulnerabilityAlertsCalls int
	fakeClient := client
	baseGraphQL := fakeClient.graphql
	fakeClient.graphql = func(query string, variables map[string]any, out any) error {
		if !strings.Contains(query, "vulnerabilityAlerts") {
			return baseGraphQL(query, variables, out)
		}
		vulnerabilityAlertsCalls++
		response, ok := out.(*vulnerabilityAlertsPullRequestsResponse)
		if !ok {
			return fmt.Errorf("unexpected GraphQL output type %T", out)
		}
		response.Repository = &struct {
			VulnerabilityAlerts struct {
				PageInfo struct {
					HasNextPage bool   `json:"hasNextPage"`
					EndCursor   string `json:"endCursor"`
				} `json:"pageInfo"`
				Nodes []vulnerabilityAlertPullRequestNode `json:"nodes"`
			} `json:"vulnerabilityAlerts"`
		}{}
		// Always report another page available, simulating a repository
		// with far more alerts than any reasonable page budget.
		response.Repository.VulnerabilityAlerts.PageInfo.HasNextPage = true
		response.Repository.VulnerabilityAlerts.PageInfo.EndCursor = "next"
		return nil
	}

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	if _, err := NewDependabotCollector(client, options).Collect(context.Background(), "test"); err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	const maxAlertPages = 5
	if vulnerabilityAlertsCalls != maxAlertPages {
		t.Errorf("vulnerabilityAlerts GraphQL calls = %d, want exactly %d (the page budget)", vulnerabilityAlertsCalls, maxAlertPages)
	}
}

// TestDependabotCollectMatchesVulnerablePackageWithoutLiveLink verifies the
// package-name fallback: a real repository can have a vulnerability alert
// whose dependabotUpdate link points at a pull request that has since been
// closed and superseded (or has no link at all), while a currently open pull
// request still bumps that exact package. That open pull request must still
// be counted as a security update, matched by package name from the title.
func TestDependabotCollectMatchesVulnerablePackageWithoutLiveLink(t *testing.T) {
	client := newDependabotFakeClient()
	baseRepoResponses(t, client, nil)
	client.securityUpdateStalePackages = map[string]bool{"cryptography": true}

	pr := pullRequest{Number: 60, Title: "Bump cryptography from 2.6.1 to 50.0.0", Body: "Bumps cryptography from 2.6.1 to 50.0.0."}
	pr.User.Login = "dependabot[bot]"
	unrelated := pullRequest{Number: 61, Title: "Bump js-yaml from 3.13.1 to 3.15.1 in /front-end", Body: "Bumps js-yaml from 3.13.1 to 3.15.1."}
	unrelated.User.Login = "dependabot[bot]"
	client.set("repos/acme/repo/pulls", []pullRequest{pr, unrelated})

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if repo.PullRequests.OpenSecurityUpdates != 1 {
		t.Errorf("open security updates = %d, want 1 (PR #60 should match the cryptography package name)", repo.PullRequests.OpenSecurityUpdates)
	}
	if repo.PullRequests.OpenVersionUpdates != 1 {
		t.Errorf("open version updates = %d, want 1 (PR #61 does not mention cryptography)", repo.PullRequests.OpenVersionUpdates)
	}
}

// TestDependabotCollectMatchesVulnerablePackageInGroupedUpdateBody verifies
// that a grouped-update pull request (whose title never names individual
// packages, for example "Bump the pip group across 1 directory with 6
// updates") is still matched by package name via its body, which lists each
// bumped dependency in a table.
func TestDependabotCollectMatchesVulnerablePackageInGroupedUpdateBody(t *testing.T) {
	client := newDependabotFakeClient()
	baseRepoResponses(t, client, nil)
	client.securityUpdateStalePackages = map[string]bool{"tqdm": true}

	pr := pullRequest{
		Number: 4,
		Title:  "Bump the pip group across 1 directory with 6 updates",
		Body:   "Bumps the pip group with 6 updates in the / directory:\n\n| Package | From | To |\n| --- | --- | --- |\n| aiohttp | 3.8.5 | 3.9.4 |\n| tqdm | 4.66.1 | 4.66.3 |\n",
	}
	pr.User.Login = "dependabot[bot]"
	client.set("repos/acme/repo/pulls", []pullRequest{pr})

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if repo.PullRequests.OpenSecurityUpdates != 1 {
		t.Errorf("open security updates = %d, want 1 (tqdm appears only in the body's dependency table)", repo.PullRequests.OpenSecurityUpdates)
	}
}

// TestDependabotCollectFallsBackToBodyHeuristicWhenLinkageUnavailable
// verifies that when the vulnerabilityAlerts GraphQL query cannot be
// evaluated, pull request classification degrades to the best-effort GHSA
// body heuristic instead of losing the split entirely.
func TestDependabotCollectFallsBackToBodyHeuristicWhenLinkageUnavailable(t *testing.T) {
	client := newDependabotFakeClient()
	baseRepoResponses(t, client, nil)
	client.securityUpdatePRsErr = fmt.Errorf("boom")

	createdAt := time.Now().Add(-1 * time.Hour)
	pr := pullRequest{Number: 9, Body: "Bumps foo from 1.0.0 to 1.0.1 to fix GHSA-xxxx-xxxx-xxxx.", CreatedAt: &createdAt}
	pr.User.Login = "dependabot[bot]"
	client.set("repos/acme/repo/pulls", []pullRequest{pr})

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if repo.PullRequests.OpenSecurityUpdates != 1 {
		t.Errorf("open security updates = %d, want 1 (fallback heuristic should still match GHSA-)", repo.PullRequests.OpenSecurityUpdates)
	}
	if len(repo.Errors) == 0 {
		t.Error("expected the failed vulnerability alert linkage query to be recorded in Errors")
	}
}

func TestDependabotCollectFlagsMissingTransitiveCoverage(t *testing.T) {
	client := newDependabotFakeClient()
	pomNode := dependencyGraphManifestNode{Filename: "pom.xml", Parseable: true, DependenciesCount: 2}
	pomNode.Dependencies.Nodes = directDependencyNodes(2)
	baseRepoResponses(t, client, []dependencyGraphManifestNode{pomNode})
	// No .github/workflows directory is registered, so detectAutoSubmission
	// finds nothing and the gap is left unmitigated.

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if repo.Status.DependencyGraphCoverage != model.GraphCoveragePartial {
		t.Fatalf("coverage = %q, want partial", repo.Status.DependencyGraphCoverage)
	}
	if repo.Status.Overall != model.SeverityDegraded {
		t.Fatalf("overall = %q, want degraded (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
	if len(repo.DependencyGraph.ManifestsMissingTransitive) != 1 || repo.DependencyGraph.ManifestsMissingTransitive[0] != "pom.xml" {
		t.Errorf("manifests missing transitive = %v, want [pom.xml]", repo.DependencyGraph.ManifestsMissingTransitive)
	}
}

func TestDependabotCollectRecognizesAutoSubmissionMitigation(t *testing.T) {
	client := newDependabotFakeClient()
	pomNode := dependencyGraphManifestNode{Filename: "pom.xml", Parseable: true, DependenciesCount: 2}
	pomNode.Dependencies.Nodes = directDependencyNodes(2)
	baseRepoResponses(t, client, []dependencyGraphManifestNode{pomNode})

	client.set("repos/acme/repo/contents/.github/workflows", []contentsEntry{
		{Type: "file", Name: "submit.yml", Path: ".github/workflows/submit.yml"},
	})
	workflow := "jobs:\n  submit:\n    steps:\n      - uses: advanced-security/maven-dependency-submission-action@v4\n"
	client.set("repos/acme/repo/contents/.github/workflows/submit.yml", map[string]any{
		"type":    "file",
		"name":    "submit.yml",
		"path":    ".github/workflows/submit.yml",
		"content": base64.StdEncoding.EncodeToString([]byte(workflow)),
	})

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if repo.Status.DependencyGraphCoverage != model.GraphCoverageMitigated {
		t.Fatalf("coverage = %q, want mitigated (auto-submission detected: %v, action: %q)",
			repo.Status.DependencyGraphCoverage, repo.DependencyGraph.AutoSubmissionDetected, repo.DependencyGraph.AutoSubmissionAction)
	}
	if repo.Status.Overall != model.SeverityHealthy {
		t.Fatalf("overall = %q, want healthy once mitigated (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
}

// TestDependabotCollectFlagsUnresolvedManifestWithUnknownRelationships
// verifies the real shape GitHub returns for an unresolved Maven/NuGet
// manifest (no lockfile, no build-time submission): every dependency has
// relationship "unknown", not "direct". The gap must still be flagged; a
// check that only recognized "direct" (and treated anything else, including
// "unknown", as evidence of resolution) would silently miss this, which is
// the actual shape observed for a real static-parsed pom.xml.
func TestDependabotCollectFlagsUnresolvedManifestWithUnknownRelationships(t *testing.T) {
	client := newDependabotFakeClient()
	pomNode := dependencyGraphManifestNode{Filename: "pom.xml", Parseable: true, DependenciesCount: 3}
	pomNode.Dependencies.Nodes = unknownDependencyNodes(3)
	baseRepoResponses(t, client, []dependencyGraphManifestNode{pomNode})

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if len(repo.DependencyGraph.ManifestsMissingTransitive) != 1 || repo.DependencyGraph.ManifestsMissingTransitive[0] != "pom.xml" {
		t.Errorf("manifests missing transitive = %v, want [pom.xml] (unknown-relationship dependencies must count as unresolved)", repo.DependencyGraph.ManifestsMissingTransitive)
	}
	if repo.Status.DependencyGraphCoverage != model.GraphCoveragePartial {
		t.Fatalf("coverage = %q, want partial", repo.Status.DependencyGraphCoverage)
	}
}

// TestDependabotCollectFlagsNuGetManifestMissingTransitiveCoverage verifies
// that a NuGet .csproj manifest is checked for the same static-parse gap as
// Maven/Gradle: GitHub cannot resolve NuGet transitive dependencies from a
// bare .csproj without a packages.lock.json or a build-time
// dependency-submission workflow.
func TestDependabotCollectFlagsNuGetManifestMissingTransitiveCoverage(t *testing.T) {
	client := newDependabotFakeClient()
	csprojNode := dependencyGraphManifestNode{Filename: "src/api/api.csproj", Parseable: true, DependenciesCount: 4}
	csprojNode.Dependencies.Nodes = directDependencyNodes(4)
	baseRepoResponses(t, client, []dependencyGraphManifestNode{csprojNode})

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if len(repo.DependencyGraph.ManifestsMissingTransitive) != 1 || repo.DependencyGraph.ManifestsMissingTransitive[0] != "src/api/api.csproj" {
		t.Errorf("manifests missing transitive = %v, want [src/api/api.csproj]", repo.DependencyGraph.ManifestsMissingTransitive)
	}
	if repo.Status.DependencyGraphCoverage != model.GraphCoveragePartial {
		t.Fatalf("coverage = %q, want partial", repo.Status.DependencyGraphCoverage)
	}
}

// TestDependabotCollectDetectsAutoSubmissionEvenWithoutAGap verifies that a
// build-time-resolution manifest (Maven, Gradle, or NuGet) whose dependency
// graph already shows transitive dependencies (so there is no coverage gap
// to mitigate) still checks for and surfaces a known dependency-submission
// workflow, rather than leaving AutoSubmissionDetected/Action blank simply
// because there was nothing left to fix. This is the common real-world case
// of a repository whose auto-submission workflow is already working.
func TestDependabotCollectDetectsAutoSubmissionEvenWithoutAGap(t *testing.T) {
	client := newDependabotFakeClient()
	csprojNode := dependencyGraphManifestNode{Filename: "api.csproj", Parseable: true, DependenciesCount: 200}
	csprojNode.Dependencies.Nodes = relationshipDependencyNodes("transitive", 200)
	baseRepoResponses(t, client, []dependencyGraphManifestNode{csprojNode})

	client.set("repos/acme/repo/contents/.github/workflows", []contentsEntry{
		{Type: "file", Name: "submit.yml", Path: ".github/workflows/submit.yml"},
	})
	workflow := "jobs:\n  submit:\n    steps:\n      - uses: advanced-security/component-detection-dependency-submission-action@v0\n"
	client.set("repos/acme/repo/contents/.github/workflows/submit.yml", map[string]any{
		"type":    "file",
		"name":    "submit.yml",
		"path":    ".github/workflows/submit.yml",
		"content": base64.StdEncoding.EncodeToString([]byte(workflow)),
	})

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if len(repo.DependencyGraph.ManifestsMissingTransitive) != 0 {
		t.Fatalf("manifests missing transitive = %v, want none (this manifest already shows transitive dependencies)", repo.DependencyGraph.ManifestsMissingTransitive)
	}
	if repo.Status.DependencyGraphCoverage != model.GraphCoverageComplete {
		t.Fatalf("coverage = %q, want complete", repo.Status.DependencyGraphCoverage)
	}
	if !repo.DependencyGraph.AutoSubmissionDetected {
		t.Error("auto submission detected = false, want true (must not stay blank just because coverage is already complete)")
	}
	if !strings.Contains(repo.DependencyGraph.AutoSubmissionAction, "component-detection-dependency-submission-action") {
		t.Errorf("auto submission action = %q, want the component-detection-dependency-submission-action marker", repo.DependencyGraph.AutoSubmissionAction)
	}
}

// TestDependabotCollectDetectsNativeAutoSubmissionFromSBOM verifies the fix
// for a real repository (no workflow files at all) whose transitive NuGet
// coverage came from GitHub's native, no-workflow "Automatic Dependency
// Submission" repository toggle. detectAutoSubmission's workflow-content
// scan cannot see this, since there is no workflow file; the SBOM export's
// creationInfo.creators lists the mechanism instead.
func TestDependabotCollectDetectsNativeAutoSubmissionFromSBOM(t *testing.T) {
	client := newDependabotFakeClient()
	csprojNode := dependencyGraphManifestNode{Filename: "api.csproj", Parseable: true, DependenciesCount: 200}
	csprojNode.Dependencies.Nodes = relationshipDependencyNodes("transitive", 200)
	baseRepoResponses(t, client, []dependencyGraphManifestNode{csprojNode})
	// No .github/workflows directory is registered, so detectAutoSubmission
	// finds nothing, forcing the SBOM fallback path.

	client.set("repos/acme/repo/dependency-graph/sbom", map[string]any{
		"sbom": map[string]any{
			"creationInfo": map[string]any{
				"creators": []string{
					"Tool: protobom-v0.0.0-dirty",
					"Tool: GitHub.com-Dependency-Graph",
					"Tool: Automatic Dependency Submission",
				},
			},
		},
	})

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if !repo.DependencyGraph.AutoSubmissionDetected {
		t.Error("auto submission detected = false, want true (the SBOM names a non-baseline submission tool)")
	}
	if repo.DependencyGraph.AutoSubmissionAction != "Automatic Dependency Submission" {
		t.Errorf("auto submission action = %q, want %q", repo.DependencyGraph.AutoSubmissionAction, "Automatic Dependency Submission")
	}
}

// TestDependabotCollectSBOMBaselineCreatorsDoNotCountAsAutoSubmission
// verifies that a repository whose SBOM lists only the baseline tools every
// export includes (the SBOM generator library and the generic dependency
// graph service marker) is not mistaken for having any build-time
// submission mechanism at all.
func TestDependabotCollectSBOMBaselineCreatorsDoNotCountAsAutoSubmission(t *testing.T) {
	client := newDependabotFakeClient()
	csprojNode := dependencyGraphManifestNode{Filename: "api.csproj", Parseable: true, DependenciesCount: 200}
	csprojNode.Dependencies.Nodes = relationshipDependencyNodes("transitive", 200)
	baseRepoResponses(t, client, []dependencyGraphManifestNode{csprojNode})

	client.set("repos/acme/repo/dependency-graph/sbom", map[string]any{
		"sbom": map[string]any{
			"creationInfo": map[string]any{
				"creators": []string{
					"Tool: protobom-v0.0.0-dirty",
					"Tool: GitHub.com-Dependency-Graph",
				},
			},
		},
	})

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if repo.DependencyGraph.AutoSubmissionDetected {
		t.Errorf("auto submission detected = true, want false (only baseline SBOM creators were present, action %q)", repo.DependencyGraph.AutoSubmissionAction)
	}
}

// TestDependabotCollectSBOMSignalNeverMasksARealTransitiveGap is the key
// safety property of the SBOM-based check: GitHub's native auto-submission
// toggle can be enabled repo-wide while still leaving one manifest in a
// monorepo genuinely unresolved (a documented limitation for complex .NET
// projects). The SBOM signal must only ever be consulted when there is no
// remaining ManifestsMissingTransitive gap; it must never reclassify a real,
// still-unresolved manifest as mitigated just because some other part of
// the repository has a submission tool active.
func TestDependabotCollectSBOMSignalNeverMasksARealTransitiveGap(t *testing.T) {
	client := newDependabotFakeClient()
	csprojNode := dependencyGraphManifestNode{Filename: "unresolved.csproj", Parseable: true, DependenciesCount: 2}
	csprojNode.Dependencies.Nodes = directDependencyNodes(2)
	baseRepoResponses(t, client, []dependencyGraphManifestNode{csprojNode})
	// No .github/workflows directory is registered, so detectAutoSubmission
	// finds nothing here either.

	// The SBOM nonetheless reports a non-baseline tool, simulating a
	// repository where the native toggle is enabled but did not resolve
	// every manifest.
	client.set("repos/acme/repo/dependency-graph/sbom", map[string]any{
		"sbom": map[string]any{
			"creationInfo": map[string]any{
				"creators": []string{
					"Tool: protobom-v0.0.0-dirty",
					"Tool: GitHub.com-Dependency-Graph",
					"Tool: Automatic Dependency Submission",
				},
			},
		},
	})

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if repo.Status.DependencyGraphCoverage != model.GraphCoveragePartial {
		t.Fatalf("coverage = %q, want partial: the SBOM signal must never override a real remaining gap", repo.Status.DependencyGraphCoverage)
	}
	if repo.DependencyGraph.AutoSubmissionDetected {
		t.Error("auto submission detected = true, want false: the SBOM signal must not be consulted while a manifest is still unresolved")
	}
}

// TestDependabotCollectRecognizesEcosystemSpecificSubmissionActions verifies
// coverage of dependency submission Actions beyond Maven/Gradle/Component
// Detection: real, marketplace-published Actions exist for Go, Mill,
// Mix/Elixir, and Scala/sbt, none of whose repository names contain the
// generic "-action" or "actions/dependency-submission" substrings the
// original marker list matched on, so each needs its own explicit entry or
// it is silently invisible to detection.
func TestDependabotCollectRecognizesEcosystemSpecificSubmissionActions(t *testing.T) {
	cases := []struct {
		name      string
		reference string
		wantID    string
	}{
		{name: "go", reference: "uses: actions/go-dependency-submission@v2", wantID: "actions/go-dependency-submission"},
		{name: "mill", reference: "uses: ckipp01/mill-dependency-submission@v1", wantID: "ckipp01/mill-dependency-submission"},
		{name: "mix", reference: "uses: erlef/mix-dependency-submission@v1", wantID: "erlef/mix-dependency-submission"},
		{name: "rebar3", reference: "uses: erlef/rebar3-dependency-submission@v1", wantID: "erlef/rebar3-dependency-submission"},
		{name: "sbt", reference: "uses: scalacenter/sbt-dependency-submission@v2", wantID: "scalacenter/sbt-dependency-submission"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			client := newDependabotFakeClient()
			csprojNode := dependencyGraphManifestNode{Filename: "app.csproj", Parseable: true, DependenciesCount: 2}
			csprojNode.Dependencies.Nodes = directDependencyNodes(2)
			baseRepoResponses(t, client, []dependencyGraphManifestNode{csprojNode})
			client.set("repos/acme/repo/contents/.github/workflows", []contentsEntry{
				{Type: "file", Name: "submit.yml", Path: ".github/workflows/submit.yml"},
			})
			workflow := "jobs:\n  submit:\n    steps:\n      - " + testCase.reference + "\n"
			client.set("repos/acme/repo/contents/.github/workflows/submit.yml", map[string]any{
				"type":    "file",
				"name":    "submit.yml",
				"path":    ".github/workflows/submit.yml",
				"content": base64.StdEncoding.EncodeToString([]byte(workflow)),
			})

			options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
			report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
			if err != nil {
				t.Fatalf("Collect returned an error: %v", err)
			}
			repo := report.Repositories[0]
			if !repo.DependencyGraph.AutoSubmissionDetected {
				t.Fatalf("auto submission detected = false, want true for %q", testCase.reference)
			}
			if repo.DependencyGraph.AutoSubmissionAction != testCase.wantID {
				t.Errorf("auto submission action = %q, want %q", repo.DependencyGraph.AutoSubmissionAction, testCase.wantID)
			}
		})
	}
}

// TestDependabotCollectRecognizesCustomDependencySubmissionAPIUsage verifies
// that a workflow calling the dependency submission API's REST endpoint
// directly (built with GitHub's own Dependency Submission Toolkit SDK, or
// any other bespoke submitter with no published Action to match on) is
// still detected, and is reported with a distinct, clearly non-marketplace
// action identifier rather than being indistinguishable from a known Action
// or silently invisible.
func TestDependabotCollectRecognizesCustomDependencySubmissionAPIUsage(t *testing.T) {
	client := newDependabotFakeClient()
	csprojNode := dependencyGraphManifestNode{Filename: "app.csproj", Parseable: true, DependenciesCount: 2}
	csprojNode.Dependencies.Nodes = directDependencyNodes(2)
	baseRepoResponses(t, client, []dependencyGraphManifestNode{csprojNode})

	client.set("repos/acme/repo/contents/.github/workflows", []contentsEntry{
		{Type: "file", Name: "submit.yml", Path: ".github/workflows/submit.yml"},
	})
	workflow := "jobs:\n  submit:\n    steps:\n      - run: |\n          curl -X POST https://api.github.com/repos/acme/repo/dependency-graph/snapshots -d @snapshot.json\n"
	client.set("repos/acme/repo/contents/.github/workflows/submit.yml", map[string]any{
		"type":    "file",
		"name":    "submit.yml",
		"path":    ".github/workflows/submit.yml",
		"content": base64.StdEncoding.EncodeToString([]byte(workflow)),
	})

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if !repo.DependencyGraph.AutoSubmissionDetected {
		t.Fatal("auto submission detected = false, want true for a direct dependency-graph/snapshots API call")
	}
	if repo.DependencyGraph.AutoSubmissionAction != customAutoSubmissionActionID {
		t.Errorf("auto submission action = %q, want %q", repo.DependencyGraph.AutoSubmissionAction, customAutoSubmissionActionID)
	}
	if strings.Contains(repo.DependencyGraph.AutoSubmissionAction, "/") {
		t.Error("a custom submitter's action id must not look like a known marketplace \"owner/repo\" slug")
	}
}

func TestDependabotCollectConfigDepthNeverReportsHealthy(t *testing.T) {
	client := newDependabotFakeClient()
	baseRepoResponses(t, client, nil)

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthConfig}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if repo.Status.Overall != model.SeverityUnknown {
		t.Fatalf("config depth overall = %q, want unknown (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
	if repo.Status.DependencyGraph != model.FeatureNotEvaluated {
		t.Errorf("dependency graph = %q, want not-evaluated at config depth", repo.Status.DependencyGraph)
	}
}

func TestDependabotCollectDiagnosticsDetectsDependencyReview(t *testing.T) {
	client := newDependabotFakeClient()
	baseRepoResponses(t, client, nil)

	rule := branchRule{Type: "required_status_checks"}
	rule.Parameters.RequiredStatusChecks = []struct {
		Context string `json:"context"`
	}{{Context: "dependency review"}}
	client.set("repos/acme/repo/rules/branches/main", []branchRule{rule})

	options := DependabotOptions{
		Repository: "acme/repo", Concurrency: 1, Depth: DepthDiagnostics,
		DependencyReviewCheckPattern: "dependency review",
	}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if repo.Status.DependencyReview != model.DependencyReviewEnforced {
		t.Fatalf("dependency review = %q, want enforced", repo.Status.DependencyReview)
	}
	if repo.DependencyReview.MatchedCheckContext != "dependency review" {
		t.Errorf("matched check context = %q, want %q", repo.DependencyReview.MatchedCheckContext, "dependency review")
	}
	if repo.Status.Overall != model.SeverityHealthy {
		t.Fatalf("overall = %q, want healthy (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
}

func TestDependabotCollectDiagnosticsFlagsMissingDependencyReview(t *testing.T) {
	client := newDependabotFakeClient()
	baseRepoResponses(t, client, nil)
	client.set("repos/acme/repo/rules/branches/main", []branchRule{})

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthDiagnostics}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if repo.Status.DependencyReview != model.DependencyReviewNotEnforced {
		t.Fatalf("dependency review = %q, want not-enforced", repo.Status.DependencyReview)
	}
	if repo.Status.Overall != model.SeverityDegraded {
		t.Fatalf("overall = %q, want degraded (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
}

// TestDependabotCollectSkipsDependencyReviewForTemporarySecurityAdvisoryFork
// verifies that a repository identified as one of GitHub's temporary
// private security-advisory forks (via GitHub's documented "-ghsa-xxxx-
// xxxx-xxxx" name suffix) never even attempts the branch rules request, and
// is not marked unknown or incomplete just because that request would
// otherwise 404. Real temporary-fork repositories always 404 from
// rules/rulesets regardless of the underlying repository's actual
// configuration; treating that as a collection error would incorrectly
// report every such fork as having incomplete evidence. The fixture
// deliberately does not set a visibility of "private" or any other signal
// once considered (and rejected) for this detection, since the fork's name
// suffix alone must be sufficient.
func TestDependabotCollectSkipsDependencyReviewForTemporarySecurityAdvisoryFork(t *testing.T) {
	client := newDependabotFakeClient()
	const repoPath = "repos/acme/service-ghsa-4xcm-h78r-r3ww"
	client.set(repoPath, map[string]any{
		"name":           "service-ghsa-4xcm-h78r-r3ww",
		"full_name":      "acme/service-ghsa-4xcm-h78r-r3ww",
		"html_url":       "https://github.com/acme/service-ghsa-4xcm-h78r-r3ww",
		"archived":       false,
		"fork":           false,
		"visibility":     "public",
		"default_branch": "main",
		"pushed_at":      "2024-01-01T00:00:00Z",
		"security_and_analysis": map[string]any{
			"dependabot_security_updates": map[string]any{"status": "enabled"},
		},
	})
	client.set(repoPath+"/vulnerability-alerts", true)
	client.set(repoPath+"/dependabot/alerts", []dependabotAlert{})
	client.set(repoPath+"/pulls", []pullRequest{})
	client.graphql = func(query string, _ map[string]any, out any) error {
		if strings.Contains(query, "vulnerabilityAlerts") {
			return fmt.Errorf("unexpected GraphQL output type %T", out)
		}
		response, ok := out.(*dependencyGraphManifestsResponse)
		if !ok {
			return fmt.Errorf("unexpected GraphQL output type %T", out)
		}
		response.Repository = &struct {
			DependencyGraphManifests struct {
				TotalCount int `json:"totalCount"`
				PageInfo   struct {
					HasNextPage bool   `json:"hasNextPage"`
					EndCursor   string `json:"endCursor"`
				} `json:"pageInfo"`
				Nodes []dependencyGraphManifestNode `json:"nodes"`
			} `json:"dependencyGraphManifests"`
		}{}
		return nil
	}
	// Deliberately no "repos/acme/service-ghsa-4xcm-h78r-r3ww/rules/branches/main"
	// fixture is registered: the fake client's GetJSON returns a 404
	// StatusError for any unregistered path, matching the real 404 these
	// forks always return. If collectDependencyReview made this request at
	// all despite the flag, the test would fail via the resulting
	// collection error.

	options := DependabotOptions{Repository: "acme/service-ghsa-4xcm-h78r-r3ww", Concurrency: 1, Depth: DepthDiagnostics}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if !repo.TemporarySecurityAdvisoryFork {
		t.Fatal("temporary security advisory fork = false, want true (repository name matched the -ghsa- suffix pattern)")
	}
	if repo.Status.DependencyReview != model.DependencyReviewNotEvaluated {
		t.Fatalf("dependency review = %q, want not-evaluated", repo.Status.DependencyReview)
	}
	if len(repo.Errors) != 0 {
		t.Errorf("errors = %v, want none: a temporary fork's guaranteed 404 must not be recorded as a collection error", repo.Errors)
	}
	if repo.Status.Incomplete {
		t.Error("incomplete = true, want false: skipping an inapplicable check must not mark evidence as incomplete")
	}
}

// TestIsTemporarySecurityAdvisoryForkNameDoesNotMatchOrdinaryRepositories
// locks in the false-positive this detection replaced: a repository must
// never be misidentified as a temporary security-advisory fork merely for
// being private or internal (GitHub populates a non-empty temp_clone_token,
// and the private/internal visibility itself, on every ordinary
// private/internal repository, not just these forks), nor for merely
// containing "ghsa" somewhere in its name without the full, specific
// "-ghsa-xxxx-xxxx-xxxx" suffix.
func TestIsTemporarySecurityAdvisoryForkNameDoesNotMatchOrdinaryRepositories(t *testing.T) {
	ordinary := []string{
		"beat-bot",
		"my-private-service",
		"ghsa-database-mirror",
		"ghsa-4xcm-h78r-r3ww-archive",
		"service-ghsa-4xcm-h78r",
	}
	for _, name := range ordinary {
		if isTemporarySecurityAdvisoryForkName(name) {
			t.Errorf("isTemporarySecurityAdvisoryForkName(%q) = true, want false", name)
		}
	}

	forks := []string{
		"spdx-examples-ghsa-4xcm-h78r-r3ww",
		"juice-shop-felickz-run1grouped-ghsa-mhmh-f55p-hr88",
	}
	for _, name := range forks {
		if !isTemporarySecurityAdvisoryForkName(name) {
			t.Errorf("isTemporarySecurityAdvisoryForkName(%q) = false, want true", name)
		}
	}
}

// TestDependabotCollectDetectsPausedWithZeroOpenPullRequests verifies that
// the automated-security-fixes endpoint's "paused" field is used even when
// there are no open Dependabot pull requests at all to carry the
// "dependabot-paused" label, which the label-only heuristic could never
// detect on its own.
func TestDependabotCollectDetectsPausedWithZeroOpenPullRequests(t *testing.T) {
	client := newDependabotFakeClient()
	baseRepoResponses(t, client, nil)
	client.set("repos/acme/repo/automated-security-fixes", map[string]any{"enabled": true, "paused": true})

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if repo.Status.VersionUpdates != model.VersionUpdatesPausedInactivity {
		t.Errorf("version updates = %q, want paused-inactivity", repo.Status.VersionUpdates)
	}
}

// TestDependabotCollectAuthoritativePausedStateOverridesStaleLabel verifies
// that when the automated-security-fixes endpoint says a repository is not
// paused, a stale "dependabot-paused" label lingering on an open pull
// request (which can lag the real state) does not incorrectly mark the
// repository as paused.
func TestDependabotCollectAuthoritativePausedStateOverridesStaleLabel(t *testing.T) {
	client := newDependabotFakeClient()
	baseRepoResponses(t, client, nil)
	client.set("repos/acme/repo/automated-security-fixes", map[string]any{"enabled": true, "paused": false})

	pr := pullRequest{Number: 1, Body: "Bumps foo from 1.0.0 to 1.0.1"}
	pr.User.Login = "dependabot[bot]"
	pr.Labels = []struct {
		Name string `json:"name"`
	}{{Name: "dependabot-paused"}}
	client.set("repos/acme/repo/pulls", []pullRequest{pr})

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if repo.Status.VersionUpdates == model.VersionUpdatesPausedInactivity {
		t.Error("version updates should not be paused-inactivity: the authoritative check said paused=false")
	}
	if repo.PullRequests.PausedForInactivity {
		t.Error("paused for inactivity should be false: the authoritative check should override the stale label")
	}
}

func TestDependabotCollectRequiresScope(t *testing.T) {
	client := newDependabotFakeClient()
	_, err := NewDependabotCollector(client, DependabotOptions{Concurrency: 1}).Collect(context.Background(), "test")
	if err == nil || !strings.Contains(err.Error(), "no organizations to scan") {
		t.Fatalf("expected a scope error, got %v", err)
	}
}
