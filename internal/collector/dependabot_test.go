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

	// paginatedOverrides lets a test take full control of GetPaginatedJSON
	// for a given path prefix, so it can simulate multiple pages (calling
	// collect more than once) instead of the default single-call behavior
	// lookup-based responses give. Used for exercising pagination-cap
	// truncation.
	paginatedOverrides map[string]func(collect func([]byte) error) error

	// manifestFollowup configures the response to the follow-up
	// node(id:)-based query manifestHasTransitiveDependencyBeyondSample
	// issues when a manifest's initial dependencies(first:100) sample was
	// capped. Keyed by manifest ID; a test registers one entry per manifest
	// it wants to control. If unset entirely (nil map or no matching key),
	// baseRepoResponses' default graphql handler reports hasNextPage=false
	// with no further dependencies, i.e. "nothing more to find".
	manifestFollowup map[string]func(cursor string) (relationships []string, hasNextPage bool, nextCursor string)

	mu     sync.Mutex
	warned map[string]bool
}

func newDependabotFakeClient() *dependabotFakeClient {
	return &dependabotFakeClient{
		responses:                   map[string]any{},
		warned:                      map[string]bool{},
		securityUpdatePRNumbers:     map[int]bool{},
		securityUpdateStalePackages: map[string]bool{},
		paginatedOverrides:          map[string]func(collect func([]byte) error) error{},
		manifestFollowup:            map[string]func(cursor string) ([]string, bool, string){},
	}
}

// setPaginated registers a GetPaginatedJSON override for any request whose
// path starts with prefix, giving a test full control over how many times
// collect is invoked (simulating multiple pages).
func (f *dependabotFakeClient) setPaginated(prefix string, fn func(collect func([]byte) error) error) {
	f.paginatedOverrides[prefix] = fn
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
	for prefix, fn := range f.paginatedOverrides {
		if strings.HasPrefix(path, prefix) {
			return fn(collect)
		}
	}
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

	client.graphql = func(query string, variables map[string]any, out any) error {
		if strings.Contains(query, "node(id:") {
			response, ok := out.(*manifestDependenciesPageResponse)
			if !ok {
				return fmt.Errorf("unexpected GraphQL output type %T", out)
			}
			id, _ := variables["id"].(string)
			cursor, _ := variables["cursor"].(string)
			var relationships []string
			hasNextPage := false
			nextCursor := ""
			if fn, ok := client.manifestFollowup[id]; ok {
				relationships, hasNextPage, nextCursor = fn(cursor)
			}
			response.Node = &struct {
				Dependencies struct {
					PageInfo struct {
						HasNextPage bool   `json:"hasNextPage"`
						EndCursor   string `json:"endCursor"`
					} `json:"pageInfo"`
					Nodes []struct {
						Relationship string `json:"relationship"`
					} `json:"nodes"`
				} `json:"dependencies"`
			}{}
			response.Node.Dependencies.PageInfo.HasNextPage = hasNextPage
			response.Node.Dependencies.PageInfo.EndCursor = nextCursor
			for _, relationship := range relationships {
				response.Node.Dependencies.Nodes = append(response.Node.Dependencies.Nodes, struct {
					Relationship string `json:"relationship"`
				}{Relationship: relationship})
			}
			return nil
		}
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

// TestDependabotCollectReportsVBProjAsNuGetEcosystem verifies that a .vbproj
// manifest, which buildTimeResolutionManifest already treats as a NuGet
// build-time-resolution gap, is also classified as the "nuget" ecosystem by
// manifestEcosystem — the two functions had drifted apart, which left a
// .vbproj-only repository showing no ecosystem at all in
// DependencyGraph.Ecosystems despite having a real coverage gap.
func TestDependabotCollectReportsVBProjAsNuGetEcosystem(t *testing.T) {
	client := newDependabotFakeClient()
	vbprojNode := dependencyGraphManifestNode{Filename: "src/api/api.vbproj", Parseable: true, DependenciesCount: 4}
	vbprojNode.Dependencies.Nodes = directDependencyNodes(4)
	baseRepoResponses(t, client, []dependencyGraphManifestNode{vbprojNode})

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if len(repo.DependencyGraph.Ecosystems) != 1 || repo.DependencyGraph.Ecosystems[0] != "nuget" {
		t.Fatalf("ecosystems = %v, want [nuget]", repo.DependencyGraph.Ecosystems)
	}
	if len(repo.DependencyGraph.ManifestsMissingTransitive) != 1 || repo.DependencyGraph.ManifestsMissingTransitive[0] != "src/api/api.vbproj" {
		t.Errorf("manifests missing transitive = %v, want [src/api/api.vbproj]", repo.DependencyGraph.ManifestsMissingTransitive)
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

// TestDependabotCollectSBOMPersonAndOrganizationCreatorsAreNotTools verifies
// that non-tool SPDX creator entries (Person:/Organization:, as opposed to
// Tool:) are never mistaken for an unrecognized auto-submission tool.
// strings.TrimPrefix returns its input unchanged when the prefix is absent,
// so without an explicit "is this actually a Tool: entry" check, a
// "Person: Jane Doe" creator would pass straight through as if it were a
// real, unrecognized tool name.
func TestDependabotCollectSBOMPersonAndOrganizationCreatorsAreNotTools(t *testing.T) {
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
					"Person: Jane Doe",
					"Organization: Acme Corp",
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
		t.Errorf("auto submission detected = true, want false: Person/Organization creator entries must not be "+
			"mistaken for an unrecognized tool (action %q)", repo.DependencyGraph.AutoSubmissionAction)
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

// TestDependabotCollectDoesNotMisclassifyGenuineErrorsAsNotFound verifies
// that a real collection failure whose message happens to mention "404" or
// "not found" (for example a transient gateway error relayed from a proxy,
// or a permission error whose body happens to quote a 404 from somewhere
// else) is never misinterpreted as "file does not exist" just because of
// substring matching against err.Error(). Only a genuine *ghapi.StatusError
// with StatusCode 404 should be treated that way.
func TestDependabotCollectDoesNotMisclassifyGenuineErrorsAsNotFound(t *testing.T) {
	client := newDependabotFakeClient()
	baseRepoResponses(t, client, nil)
	client.set("repos/acme/repo/contents/.github/dependabot.yml",
		fmt.Errorf("upstream proxy returned an unexpected body mentioning 404 and not found, but this is not itself a 404"))
	client.set("repos/acme/repo/contents/.github/dependabot.yaml",
		fmt.Errorf("upstream proxy returned an unexpected body mentioning 404 and not found, but this is not itself a 404"))

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if repo.Status.VersionUpdates != model.VersionUpdatesUnknown {
		t.Fatalf("version updates = %q, want unknown: a non-StatusError mentioning \"404\" in its text must not be "+
			"treated as a real 404 and silently skipped", repo.Status.VersionUpdates)
	}
	found := false
	for _, e := range repo.Errors {
		if strings.Contains(e, "dependabot.yml") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a recorded collection error for dependabot.yml, got: %v", repo.Errors)
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

// TestDependabotCollectUncheckedPullRequestNeverReportsHealthy is the core
// regression test for the most impactful fix in this batch: repo.Errors
// accumulating evidence-collection failures must always set
// Status.Incomplete, which must in turn prevent a healthy verdict.
// Previously, Incomplete was never set anywhere in this collector, so a
// repository whose pull request check status could not be established (the
// combined-status call succeeds, but the check-runs call fails) would
// silently report healthy despite the gap in evidence.
func TestDependabotCollectUncheckedPullRequestNeverReportsHealthy(t *testing.T) {
	client := newDependabotFakeClient()
	baseRepoResponses(t, client, nil)

	createdAt := time.Now().Add(-1 * time.Hour)
	pr := pullRequest{Number: 1, Body: "Bumps foo from 1.0.0 to 1.0.1", CreatedAt: &createdAt}
	pr.User.Login = "dependabot[bot]"
	pr.Head.SHA = "abc123"
	client.set("repos/acme/repo/pulls", []pullRequest{pr})
	client.set("repos/acme/repo/commits/abc123/status", combinedStatus{State: "success"})
	// Deliberately registered as a 404 error (not simply omitted): the fake
	// client's longest-prefix lookup would otherwise fall back to the
	// broader "repos/acme/repo" repository fixture and decode it into an
	// empty, error-free checkRunsResponse, masking the fetch failure this
	// test exists to exercise.
	client.set("repos/acme/repo/commits/abc123/check-runs", &ghapi.StatusError{StatusCode: http.StatusNotFound, URL: "check-runs", Message: "Not Found"})

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if repo.Status.PullRequestHealth != model.PRHealthUnknown {
		t.Fatalf("pull request health = %q, want unknown", repo.Status.PullRequestHealth)
	}
	if !repo.Status.Incomplete {
		t.Fatal("Status.Incomplete = false, want true: a collection error was recorded in repo.Errors")
	}
	if repo.Status.Overall != model.SeverityUnknown {
		t.Fatalf("overall = %q, want unknown: Incomplete must prevent a healthy verdict (reasons: %v, errors: %v)",
			repo.Status.Overall, repo.Status.Reasons, repo.Errors)
	}
	if len(repo.Errors) == 0 {
		t.Error("expected a recorded collection error for the unchecked pull request")
	}
}

// TestDependabotCollectDetectsFailingChecksFromChecksAPIOnly verifies that a
// failing GitHub Actions check run is detected even when the legacy
// Combined Status endpoint reports success, since Actions posts through the
// separate Checks API that endpoint never reflects.
func TestDependabotCollectDetectsFailingChecksFromChecksAPIOnly(t *testing.T) {
	client := newDependabotFakeClient()
	baseRepoResponses(t, client, nil)

	createdAt := time.Now().Add(-1 * time.Hour)
	pr := pullRequest{Number: 1, Body: "Bumps foo from 1.0.0 to 1.0.1", CreatedAt: &createdAt}
	pr.User.Login = "dependabot[bot]"
	pr.Head.SHA = "abc123"
	client.set("repos/acme/repo/pulls", []pullRequest{pr})
	client.set("repos/acme/repo/commits/abc123/status", combinedStatus{State: "success"})
	client.set("repos/acme/repo/commits/abc123/check-runs", checkRunsResponse{
		CheckRuns: []struct {
			Status     string `json:"status"`
			Conclusion string `json:"conclusion"`
		}{{Status: "completed", Conclusion: "failure"}},
	})

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if repo.PullRequests.OpenFailingChecks != 1 {
		t.Fatalf("open failing checks = %d, want 1 (combined status alone would have missed this)", repo.PullRequests.OpenFailingChecks)
	}
	if repo.Status.PullRequestHealth != model.PRHealthFailingChecks {
		t.Fatalf("pull request health = %q, want failing-checks", repo.Status.PullRequestHealth)
	}
	if repo.Status.Overall != model.SeverityFailing {
		t.Fatalf("overall = %q, want failing (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
}

// TestDependabotCollectSkippedCheckRunsAreNotFailures verifies that
// "skipped" and "neutral" check-run conclusions (ordinary, often
// intentional outcomes, such as a path-filtered workflow that never ran for
// this pull request) are not counted as failures.
func TestDependabotCollectSkippedCheckRunsAreNotFailures(t *testing.T) {
	client := newDependabotFakeClient()
	baseRepoResponses(t, client, nil)

	createdAt := time.Now().Add(-1 * time.Hour)
	pr := pullRequest{Number: 1, Body: "Bumps foo from 1.0.0 to 1.0.1", CreatedAt: &createdAt}
	pr.User.Login = "dependabot[bot]"
	pr.Head.SHA = "abc123"
	client.set("repos/acme/repo/pulls", []pullRequest{pr})
	client.set("repos/acme/repo/commits/abc123/status", combinedStatus{State: "success"})
	client.set("repos/acme/repo/commits/abc123/check-runs", checkRunsResponse{
		CheckRuns: []struct {
			Status     string `json:"status"`
			Conclusion string `json:"conclusion"`
		}{
			{Status: "completed", Conclusion: "skipped"},
			{Status: "completed", Conclusion: "neutral"},
			{Status: "completed", Conclusion: "success"},
		},
	})

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if repo.PullRequests.OpenFailingChecks != 0 {
		t.Fatalf("open failing checks = %d, want 0 (skipped/neutral are not failures)", repo.PullRequests.OpenFailingChecks)
	}
	if repo.Status.PullRequestHealth != model.PRHealthHealthy {
		t.Fatalf("pull request health = %q, want healthy", repo.Status.PullRequestHealth)
	}
}

// TestDependabotCollectSumsPerEcosystemBacklogLimitsAcrossBlocks verifies the
// fix for a dependabot.yml with two update blocks for the same ecosystem
// (for example two separate npm directories): the effective backlog limit
// must be the sum of each block's own open-pull-requests-limit, not
// GitHub's default-per-block limit multiplied by the count of distinct
// ecosystems (which collapses two same-ecosystem blocks into a single
// limit-unit and reports a false backlog well before the real, combined
// limit is reached).
func TestDependabotCollectSumsPerEcosystemBacklogLimitsAcrossBlocks(t *testing.T) {
	client := newDependabotFakeClient()
	baseRepoResponses(t, client, nil)

	dependabotYML := "version: 2\nupdates:\n" +
		"  - package-ecosystem: npm\n    directory: \"/app\"\n    open-pull-requests-limit: 3\n" +
		"  - package-ecosystem: npm\n    directory: \"/tools\"\n    open-pull-requests-limit: 5\n"
	client.set("repos/acme/repo/contents/.github/dependabot.yml", map[string]any{
		"type":    "file",
		"name":    "dependabot.yml",
		"path":    ".github/dependabot.yml",
		"content": base64.StdEncoding.EncodeToString([]byte(dependabotYML)),
	})

	var pulls []pullRequest
	for i := 1; i <= 7; i++ {
		createdAt := time.Now().Add(-1 * time.Hour)
		pr := pullRequest{Number: i, Body: fmt.Sprintf("Bumps pkg%d from 1.0.0 to 1.0.1", i), CreatedAt: &createdAt}
		pr.User.Login = "dependabot[bot]"
		pr.Head.SHA = fmt.Sprintf("sha%d", i)
		client.set(fmt.Sprintf("repos/acme/repo/commits/sha%d/status", i), combinedStatus{State: "success"})
		client.set(fmt.Sprintf("repos/acme/repo/commits/sha%d/check-runs", i), checkRunsResponse{})
		pulls = append(pulls, pr)
	}
	client.set("repos/acme/repo/pulls", pulls)

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if repo.VersionUpdates.EcosystemLimits["npm"] != 8 {
		t.Fatalf("npm ecosystem limit = %d, want 8 (3 + 5 summed across both blocks)", repo.VersionUpdates.EcosystemLimits["npm"])
	}
	if repo.Status.PullRequestHealth != model.PRHealthHealthy {
		t.Fatalf("pull request health = %q, want healthy: 7 open pull requests is under the combined limit of 8 "+
			"(the old formula, defaultLimitPerBlock*uniqueEcosystems=5*1=5, would have wrongly reported backlogged)",
			repo.Status.PullRequestHealth)
	}
	if repo.Status.Overall != model.SeverityHealthy {
		t.Fatalf("overall = %q, want healthy (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
}

// TestDependabotCollectMitigationIsScopedToTheGapsEcosystem verifies the fix
// for CCR's "blank-field" follow-on: a detected submission action must only
// be treated as mitigating manifests in the ecosystem(s) it actually
// resolves. A Maven-specific submission action must not be treated as
// mitigating an unrelated NuGet manifest gap, even though some auto
// submission mechanism was found in the workflow files.
func TestDependabotCollectMitigationIsScopedToTheGapsEcosystem(t *testing.T) {
	client := newDependabotFakeClient()
	csprojNode := dependencyGraphManifestNode{Filename: "api.csproj", Parseable: true, DependenciesCount: 2}
	csprojNode.Dependencies.Nodes = directDependencyNodes(2)
	baseRepoResponses(t, client, []dependencyGraphManifestNode{csprojNode})

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
	if !repo.DependencyGraph.AutoSubmissionDetected {
		t.Fatal("auto submission detected = false, want true: the Maven action was found in a workflow file")
	}
	if repo.Status.DependencyGraphCoverage != model.GraphCoveragePartial {
		t.Fatalf("coverage = %q, want partial: a Maven-only submission action must not mitigate an unrelated NuGet gap", repo.Status.DependencyGraphCoverage)
	}
	if repo.Status.Overall != model.SeverityDegraded {
		t.Fatalf("overall = %q, want degraded (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
}

// TestDependabotCollectIgnoresCommentedOutSubmissionMarkers verifies that a
// marker referenced only inside a commented-out, disabled workflow step is
// not mistaken for active mitigation.
func TestDependabotCollectIgnoresCommentedOutSubmissionMarkers(t *testing.T) {
	client := newDependabotFakeClient()
	pomNode := dependencyGraphManifestNode{Filename: "pom.xml", Parseable: true, DependenciesCount: 2}
	pomNode.Dependencies.Nodes = directDependencyNodes(2)
	baseRepoResponses(t, client, []dependencyGraphManifestNode{pomNode})

	client.set("repos/acme/repo/contents/.github/workflows", []contentsEntry{
		{Type: "file", Name: "submit.yml", Path: ".github/workflows/submit.yml"},
	})
	workflow := "jobs:\n  submit:\n    steps:\n      # - uses: advanced-security/maven-dependency-submission-action@v4\n      - run: echo disabled\n"
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
	if repo.DependencyGraph.AutoSubmissionDetected {
		t.Errorf("auto submission detected = true, want false: the only reference was commented out (action %q)", repo.DependencyGraph.AutoSubmissionAction)
	}
	if repo.Status.DependencyGraphCoverage != model.GraphCoveragePartial {
		t.Fatalf("coverage = %q, want partial", repo.Status.DependencyGraphCoverage)
	}
}

// TestDependabotCollectIgnoresOptInGradleActions verifies that
// gradle/actions/setup-gradle and gradle/gradle-build-action, whose
// dependency-graph submission behavior defaults to disabled (opt-in via an
// explicit input), are no longer treated as evidence of active mitigation;
// only the dedicated, always-on gradle/actions/dependency-submission is.
func TestDependabotCollectIgnoresOptInGradleActions(t *testing.T) {
	client := newDependabotFakeClient()
	gradleNode := dependencyGraphManifestNode{Filename: "build.gradle", Parseable: true, DependenciesCount: 2}
	gradleNode.Dependencies.Nodes = directDependencyNodes(2)
	baseRepoResponses(t, client, []dependencyGraphManifestNode{gradleNode})

	client.set("repos/acme/repo/contents/.github/workflows", []contentsEntry{
		{Type: "file", Name: "build.yml", Path: ".github/workflows/build.yml"},
	})
	workflow := "jobs:\n  build:\n    steps:\n      - uses: gradle/actions/setup-gradle@v3\n"
	client.set("repos/acme/repo/contents/.github/workflows/build.yml", map[string]any{
		"type":    "file",
		"name":    "build.yml",
		"path":    ".github/workflows/build.yml",
		"content": base64.StdEncoding.EncodeToString([]byte(workflow)),
	})

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if repo.DependencyGraph.AutoSubmissionDetected {
		t.Errorf("auto submission detected = true, want false: setup-gradle alone does not submit by default (action %q)", repo.DependencyGraph.AutoSubmissionAction)
	}
	if repo.Status.DependencyGraphCoverage != model.GraphCoveragePartial {
		t.Fatalf("coverage = %q, want partial", repo.Status.DependencyGraphCoverage)
	}
}

// TestDependabotCollectDetectsClassicBranchProtection verifies that a
// repository enforcing its dependency-review check purely through the
// older, separate classic branch-protection system (not rulesets) is still
// recognized. GET /rules/branches/{branch} only reflects rulesets; a
// repository relying solely on classic protection was previously always
// misreported as not-enforced.
func TestDependabotCollectDetectsClassicBranchProtection(t *testing.T) {
	client := newDependabotFakeClient()
	baseRepoResponses(t, client, nil)
	client.set("repos/acme/repo/rules/branches/main", []branchRule{})
	client.set("repos/acme/repo/branches/main/protection/required_status_checks", map[string]any{
		"contexts": []string{"dependency review"},
	})

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
		t.Fatalf("dependency review = %q, want enforced (classic branch protection must also be checked)", repo.Status.DependencyReview)
	}
	if repo.DependencyReview.MatchedCheckContext != "dependency review" {
		t.Errorf("matched check context = %q, want %q", repo.DependencyReview.MatchedCheckContext, "dependency review")
	}
}

// TestDependabotCollectAlertPaginationCapRecordsTruncation verifies that
// hitting the open-alerts page budget while the last fetched page was a
// full page (a proxy for "more may exist") is recorded as a collection
// error, rather than silently reporting a truncated alert count as the
// complete picture.
func TestDependabotCollectAlertPaginationCapRecordsTruncation(t *testing.T) {
	client := newDependabotFakeClient()
	baseRepoResponses(t, client, nil)

	client.setPaginated("repos/acme/repo/dependabot/alerts", func(collect func([]byte) error) error {
		page := make([]dependabotAlert, 100)
		for i := range page {
			page[i].State = "open"
			page[i].SecurityAdvisory.Severity = "low"
		}
		encoded, err := json.Marshal(page)
		if err != nil {
			return err
		}
		// Simulate a repository with far more open alerts than the page
		// budget by always returning a full (100-item) page.
		for i := 0; i < 10; i++ {
			if err := collect(encoded); err != nil {
				return err
			}
		}
		return nil
	})

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if repo.Alerts.OpenTotal != 300 {
		t.Fatalf("open total = %d, want 300 (3 pages of 100, the page budget)", repo.Alerts.OpenTotal)
	}
	found := false
	for _, e := range repo.Errors {
		if strings.Contains(e, "stopped after 3 pages") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a truncation error in repo.Errors, got: %v", repo.Errors)
	}
	if !repo.Status.Incomplete {
		t.Error("Status.Incomplete = false, want true")
	}
	if repo.Status.Overall != model.SeverityUnknown {
		t.Fatalf("overall = %q, want unknown (truncated alert evidence must not be reported healthy)", repo.Status.Overall)
	}
}

// TestDependabotCollectPullRequestLinkagePaginationCapRecordsTruncation
// verifies that hitting the vulnerability-alert-linkage page budget while
// the server still reports more pages available is recorded as a
// collection error, since the linkage map built so far is genuinely
// partial and could misclassify a security update pull request as a
// version update.
func TestDependabotCollectPullRequestLinkagePaginationCapRecordsTruncation(t *testing.T) {
	client := newDependabotFakeClient()
	baseRepoResponses(t, client, nil)

	createdAt := time.Now().Add(-1 * time.Hour)
	pr := pullRequest{Number: 1, Body: "Bumps foo from 1.0.0 to 1.0.1", CreatedAt: &createdAt}
	pr.User.Login = "dependabot[bot]"
	pr.Head.SHA = "abc123"
	client.set("repos/acme/repo/pulls", []pullRequest{pr})
	client.set("repos/acme/repo/commits/abc123/status", combinedStatus{State: "success"})
	client.set("repos/acme/repo/commits/abc123/check-runs", checkRunsResponse{})

	baseGraphQL := client.graphql
	client.graphql = func(query string, variables map[string]any, out any) error {
		if !strings.Contains(query, "vulnerabilityAlerts") {
			return baseGraphQL(query, variables, out)
		}
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
		response.Repository.VulnerabilityAlerts.PageInfo.HasNextPage = true
		response.Repository.VulnerabilityAlerts.PageInfo.EndCursor = "next"
		return nil
	}

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	found := false
	for _, e := range repo.Errors {
		if strings.Contains(e, "vulnerability alert pull request linkage: stopped after 5 pages") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a pull request linkage truncation error in repo.Errors, got: %v", repo.Errors)
	}
	if !repo.Status.Incomplete {
		t.Error("Status.Incomplete = false, want true")
	}
}

// TestDependabotCollectFlagsUnparseableAndOversizedManifestsAsIncomplete
// verifies that a manifest the dependency graph could not parse at all, or
// one that exceeded the graph's maximum size, is surfaced as a collection
// error (not just a silently-populated list field), so it correctly
// prevents a false healthy verdict via Status.Incomplete.
func TestDependabotCollectFlagsUnparseableAndOversizedManifestsAsIncomplete(t *testing.T) {
	client := newDependabotFakeClient()
	baseRepoResponses(t, client, []dependencyGraphManifestNode{
		{Filename: "broken.json", Parseable: false},
		{Filename: "huge-lockfile.json", Parseable: true, ExceedsMaxSize: true},
	})

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if len(repo.DependencyGraph.UnparseableManifests) != 1 || repo.DependencyGraph.UnparseableManifests[0] != "broken.json" {
		t.Errorf("unparseable manifests = %v, want [broken.json]", repo.DependencyGraph.UnparseableManifests)
	}
	if len(repo.DependencyGraph.OversizedManifests) != 1 || repo.DependencyGraph.OversizedManifests[0] != "huge-lockfile.json" {
		t.Errorf("oversized manifests = %v, want [huge-lockfile.json]", repo.DependencyGraph.OversizedManifests)
	}
	if !repo.Status.Incomplete {
		t.Fatal("Status.Incomplete = false, want true: unparseable/oversized manifests are a real evidence gap")
	}
	if repo.Status.Overall != model.SeverityUnknown {
		t.Fatalf("overall = %q, want unknown (reasons: %v, errors: %v)", repo.Status.Overall, repo.Status.Reasons, repo.Errors)
	}
}

// TestDependabotCollectCappedDependencySampleIsInconclusiveNotConfirmed
// verifies that a manifest whose dependency sample was truncated by the
// GraphQL query's own per-manifest cap (only the first 100 dependencies are
// inspected), and none of the inspected dependencies were transitive, is
// not confidently reported as a confirmed transitive-coverage gap: a
// transitive relationship could still appear beyond the inspected sample.
// This test simulates exhausting manifestHasTransitiveDependencyBeyondSample's
// pagination safety cap without finding one; that remaining ambiguity must
// be recorded as an inconclusive collection note.
func TestDependabotCollectCappedDependencySampleIsInconclusiveNotConfirmed(t *testing.T) {
	client := newDependabotFakeClient()
	pomNode := dependencyGraphManifestNode{ID: "manifest-1", Filename: "pom.xml", Parseable: true, DependenciesCount: 2000}
	pomNode.Dependencies.Nodes = directDependencyNodes(100)
	pomNode.Dependencies.PageInfo.HasNextPage = true
	pomNode.Dependencies.PageInfo.EndCursor = "page1"
	baseRepoResponses(t, client, []dependencyGraphManifestNode{pomNode})
	// Every follow-up page reports more direct dependencies and always
	// another page available, so the pagination safety cap is hit without
	// ever finding a transitive relationship.
	client.manifestFollowup["manifest-1"] = func(cursor string) ([]string, bool, string) {
		return []string{"direct", "direct"}, true, cursor + "+"
	}

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if len(repo.DependencyGraph.ManifestsMissingTransitive) != 0 {
		t.Fatalf("manifests missing transitive = %v, want none: inspection was still incomplete when the safety cap was hit, "+
			"so this must not be confidently reported as a confirmed gap", repo.DependencyGraph.ManifestsMissingTransitive)
	}
	found := false
	for _, e := range repo.Errors {
		if strings.Contains(e, "inspection stopped after the pagination safety cap") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an inconclusive-coverage note in repo.Errors, got: %v", repo.Errors)
	}
	if !repo.Status.Incomplete {
		t.Error("Status.Incomplete = false, want true")
	}
	if repo.Status.Overall != model.SeverityUnknown {
		t.Fatalf("overall = %q, want unknown (an inconclusive manifest must not be silently folded into a healthy verdict)", repo.Status.Overall)
	}
}

// TestDependabotCollectPaginatesBeyondSampleAndFindsTransitiveDependency
// verifies that when a manifest's initial 100-dependency sample has no
// transitive dependency but more dependencies remain, paginating further
// and finding a transitive one there resolves the ambiguity as coverage
// complete, not a confirmed gap and not merely inconclusive — the schema
// fully supports paging past the initial sample, so this should not be left
// unresolved when the real answer is reachable.
func TestDependabotCollectPaginatesBeyondSampleAndFindsTransitiveDependency(t *testing.T) {
	client := newDependabotFakeClient()
	pomNode := dependencyGraphManifestNode{ID: "manifest-2", Filename: "pom.xml", Parseable: true, DependenciesCount: 150}
	pomNode.Dependencies.Nodes = directDependencyNodes(100)
	pomNode.Dependencies.PageInfo.HasNextPage = true
	pomNode.Dependencies.PageInfo.EndCursor = "page1"
	baseRepoResponses(t, client, []dependencyGraphManifestNode{pomNode})
	client.manifestFollowup["manifest-2"] = func(cursor string) ([]string, bool, string) {
		return []string{"transitive", "direct"}, false, ""
	}

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if len(repo.DependencyGraph.ManifestsMissingTransitive) != 0 {
		t.Fatalf("manifests missing transitive = %v, want none: a transitive dependency was found beyond the initial sample",
			repo.DependencyGraph.ManifestsMissingTransitive)
	}
	if repo.Status.DependencyGraphCoverage != model.GraphCoverageComplete {
		t.Fatalf("coverage = %q, want complete", repo.Status.DependencyGraphCoverage)
	}
	for _, e := range repo.Errors {
		if strings.Contains(e, "pom.xml") {
			t.Errorf("unexpected error for a fully-resolved manifest: %q", e)
		}
	}
}

// TestDependabotCollectPaginatesBeyondSampleAndConfirmsGap verifies that
// when pagination is able to run all the way to the end of a manifest's
// dependency list (hasNextPage eventually false) without ever finding a
// transitive dependency, the gap is now reported as confirmed — not an
// inconclusive sampling artifact — since every dependency was actually
// inspected.
func TestDependabotCollectPaginatesBeyondSampleAndConfirmsGap(t *testing.T) {
	client := newDependabotFakeClient()
	pomNode := dependencyGraphManifestNode{ID: "manifest-3", Filename: "pom.xml", Parseable: true, DependenciesCount: 150}
	pomNode.Dependencies.Nodes = directDependencyNodes(100)
	pomNode.Dependencies.PageInfo.HasNextPage = true
	pomNode.Dependencies.PageInfo.EndCursor = "page1"
	baseRepoResponses(t, client, []dependencyGraphManifestNode{pomNode})
	client.manifestFollowup["manifest-3"] = func(cursor string) ([]string, bool, string) {
		return []string{"direct", "direct"}, false, ""
	}

	options := DependabotOptions{Repository: "acme/repo", Concurrency: 1, Depth: DepthHealth}
	report, err := NewDependabotCollector(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := report.Repositories[0]
	if len(repo.DependencyGraph.ManifestsMissingTransitive) != 1 || repo.DependencyGraph.ManifestsMissingTransitive[0] != "pom.xml" {
		t.Fatalf("manifests missing transitive = %v, want [pom.xml]: every dependency was inspected and none was transitive",
			repo.DependencyGraph.ManifestsMissingTransitive)
	}
	if repo.Status.DependencyGraphCoverage != model.GraphCoveragePartial {
		t.Fatalf("coverage = %q, want partial", repo.Status.DependencyGraphCoverage)
	}
	for _, e := range repo.Errors {
		if strings.Contains(e, "inconclusive") || strings.Contains(e, "unknown, not confirmed") {
			t.Errorf("a fully-paginated manifest must not be reported as inconclusive: %q", e)
		}
	}
}
