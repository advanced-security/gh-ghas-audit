package collector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
)

// This file implements the Dependabot / software composition analysis (SCA)
// health collector. It is a sibling to collector.go (code scanning), not a
// modification of it: the two collectors read different evidence and share
// no per-repository shape, so a separate Collector type keeps the existing
// code scanning code path untouched.

// defaultDependencyReviewCheckPattern is the case-insensitive substring
// matched against required status check contexts, because there is no native
// ruleset rule type for "dependency review"; it is always enforced through a
// required status check whose name varies by configuration.
const defaultDependencyReviewCheckPattern = "dependency review"

// autoSubmissionDetector is one normalized, known build-time dependency
// submission mechanism: a marketplace Action (identified by an "owner/repo"
// workflow reference substring) or GitHub's own SBOM-recorded tool name.
// ID is the canonical, normalized identifier for the detector (its
// marketplace repository slug, or a stable name for a non-Action mechanism),
// independent of how it happens to be pinned or referenced in a given
// workflow file; Marker is the literal, lowercased substring searched for in
// workflow file content. Ecosystems lists the manifestEcosystem values this
// detector can actually resolve a transitive-dependency gap for (for
// example "maven" or "gradle"); a nil/empty Ecosystems means the detector is
// a generic, build-tool-agnostic submitter (a full SBOM export, Component
// Detection, or the raw dependency submission API) that mitigates a gap in
// any ecosystem it runs against.
type autoSubmissionDetector struct {
	ID         string
	Marker     string
	Ecosystems []string
}

// coversEcosystem reports whether d can mitigate a transitive-dependency gap
// for the given manifestEcosystem value. A detector with no Ecosystems is
// generic and covers every ecosystem.
func (d autoSubmissionDetector) coversEcosystem(ecosystem string) bool {
	if len(d.Ecosystems) == 0 {
		return true
	}
	for _, e := range d.Ecosystems {
		if strings.EqualFold(e, ecosystem) {
			return true
		}
	}
	return false
}

// knownAutoSubmissionDetectors enumerates the build-time dependency
// submission Actions GitHub documents as "pre-made actions" for the
// dependency submission API (see "Using the dependency submission API" in
// the GitHub Docs) plus every repository tagged with the "dependency-submission"
// GitHub topic that is an actual submission Action (as opposed to a debug or
// non-Action tool). Each ID is that Action's "owner/repo" marketplace slug,
// which is already the natural, stable, normalized identifier: it uniquely
// names the detector regardless of which version, branch, or fork a
// particular workflow pins. A match is treated as evidence that a
// build-time-resolution manifest gap (Maven, Gradle, NuGet, Go, Mill, Mix,
// Scala/sbt, Erlang/rebar3) is already being mitigated, or already explains
// why coverage is complete, but only for the ecosystem(s) that detector
// actually resolves (see autoSubmissionDetector.Ecosystems /
// coversEcosystem) — a Go submission action, for example, says nothing
// about an unrelated NuGet manifest gap. Matching is deliberately a broad,
// best-effort substring search rather than an exact action-version match,
// because pinned refs and forks are common; every marker here has been
// confirmed against real-world workflow files via GitHub code search.
//
// gradle/actions/setup-gradle and gradle/gradle-build-action are
// deliberately NOT included here: both actions' dependency-graph submission
// behavior defaults to disabled (opt-in via an explicit
// dependency-graph: generate-and-submit input), so a bare reference to
// either action in a workflow is not reliable evidence that submission is
// actually happening. Only gradle/actions/dependency-submission, whose sole
// purpose is submission, is a dependable signal.
var knownAutoSubmissionDetectors = []autoSubmissionDetector{
	{ID: "advanced-security/maven-dependency-submission-action", Marker: "advanced-security/maven-dependency-submission-action", Ecosystems: []string{"maven"}},
	{ID: "gradle/actions/dependency-submission", Marker: "gradle/actions/dependency-submission", Ecosystems: []string{"gradle"}},
	{ID: "advanced-security/component-detection-dependency-submission-action", Marker: "advanced-security/component-detection-dependency-submission-action"},
	{ID: "actions/go-dependency-submission", Marker: "actions/go-dependency-submission", Ecosystems: []string{"go"}},
	{ID: "ckipp01/mill-dependency-submission", Marker: "ckipp01/mill-dependency-submission", Ecosystems: []string{"mill"}},
	{ID: "erlef/mix-dependency-submission", Marker: "erlef/mix-dependency-submission", Ecosystems: []string{"mix"}},
	{ID: "erlef/rebar3-dependency-submission", Marker: "erlef/rebar3-dependency-submission", Ecosystems: []string{"rebar3"}},
	{ID: "scalacenter/sbt-dependency-submission", Marker: "scalacenter/sbt-dependency-submission", Ecosystems: []string{"sbt"}},
	{ID: "advanced-security/spdx-dependency-submission-action", Marker: "advanced-security/spdx-dependency-submission-action"},
	{ID: "advanced-security/codeql-dependency-graph-action", Marker: "advanced-security/codeql-dependency-graph-action"},
	{ID: "anchore/sbom-action", Marker: "anchore/sbom-action"},
	{ID: "pippinmole/bun-dependency-submission", Marker: "pippinmole/bun-dependency-submission", Ecosystems: []string{"bun"}},
	// Generic markers, kept last: a broad "*-dependency-submission-action"
	// or "actions/dependency-submission" reference not covered by a specific
	// entry above (a fork, a rename, or a submitter this list has not been
	// updated for yet).
	{ID: "actions/dependency-submission", Marker: "actions/dependency-submission"},
	{ID: "dependency-submission-action", Marker: "dependency-submission-action"},
}

// isGenericAutoSubmissionMarker reports whether marker is one of the two
// deliberately broad, catch-all fallback markers in
// knownAutoSubmissionDetectors (as opposed to a specific action's own
// marketplace slug).
func isGenericAutoSubmissionMarker(marker string) bool {
	return marker == "actions/dependency-submission" || marker == "dependency-submission-action"
}

// genericMarkerSubsumedBySpecificMatch reports whether a generic marker's
// match in content is redundant: some other, more specific (non-generic)
// detector's marker both contains the generic marker as a substring of its
// own name and is itself present in content. This is true for every
// specific "*-dependency-submission-action" slug and for
// "gradle/actions/dependency-submission" (which contains the generic
// "actions/dependency-submission" marker).
func genericMarkerSubsumedBySpecificMatch(content, genericMarker string) bool {
	for _, other := range knownAutoSubmissionDetectors {
		if other.Marker == genericMarker || isGenericAutoSubmissionMarker(other.Marker) {
			continue
		}
		if strings.Contains(other.Marker, genericMarker) && strings.Contains(content, other.Marker) {
			return true
		}
	}
	return false
}

// customDependencySubmissionMarker is the dependency submission API's REST
// endpoint path. Workflows built with GitHub's own Dependency Submission
// Toolkit SDK (github/dependency-submission-toolkit), or any other
// custom-built submitter, call this endpoint directly rather than a
// published, named Action; there is no marketplace slug to match on for
// these, so a reference to the endpoint itself is the only detectable
// evidence. Reported distinctly from knownAutoSubmissionDetectors so a
// custom submitter is never confused with a recognized marketplace Action.
const customDependencySubmissionMarker = "dependency-graph/snapshots"

// customAutoSubmissionActionID is the AutoSubmissionAction value used when
// only customDependencySubmissionMarker matched, so that value is always
// distinguishable at a glance from a knownAutoSubmissionDetectors ID
// (every one of which contains a "/" from its "owner/repo" slug).
const customAutoSubmissionActionID = "custom (dependency submission API)"

// DependabotOptions configures a DependabotCollector.
type DependabotOptions struct {
	Enterprise    string
	Organizations []string
	// Repository restricts the scan to a single "owner/name" repository.
	Repository string

	SkipArchived bool
	SkipForks    bool

	// Depth selects how much evidence is gathered. Empty means DepthHealth.
	Depth Depth

	Concurrency int

	Match            []string
	Exclude          []string
	VisibilityFilter []string

	// DependencyReviewCheckPattern is matched case-insensitively as a
	// substring against required status check contexts at DepthDiagnostics.
	// Empty uses defaultDependencyReviewCheckPattern.
	DependencyReviewCheckPattern string

	// Progress receives human-readable progress messages.
	Progress func(message string)
	// Verbose reports every repository by name and status as it completes,
	// instead of only a running count every 25 repositories.
	Verbose bool
	// OnRepository is invoked as each repository completes, enabling
	// streaming output for very large estates. Calls are serialized, so the
	// callback does not need to be safe for concurrent use.
	OnRepository func(repo model.DependabotRepo)

	// Now allows tests to control the clock used for report timestamps.
	Now func() time.Time
}

// DependabotCollector executes a Dependabot/SCA health collection.
type DependabotCollector struct {
	client  Client
	options DependabotOptions

	mu       sync.Mutex
	warnings []string
}

// NewDependabotCollector creates a DependabotCollector.
func NewDependabotCollector(client Client, options DependabotOptions) *DependabotCollector {
	if options.Concurrency <= 0 {
		options.Concurrency = 8
	}
	if options.Depth == "" {
		options.Depth = DepthHealth
	}
	if options.DependencyReviewCheckPattern == "" {
		options.DependencyReviewCheckPattern = defaultDependencyReviewCheckPattern
	}
	return &DependabotCollector{client: client, options: options}
}

func (c *DependabotCollector) now() time.Time {
	if c.options.Now != nil {
		return c.options.Now()
	}
	return time.Now()
}

func (c *DependabotCollector) progress(format string, args ...any) {
	if c.options.Progress == nil {
		return
	}
	c.options.Progress(fmt.Sprintf(format, args...))
}

func (c *DependabotCollector) warn(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	c.mu.Lock()
	c.warnings = append(c.warnings, message)
	c.mu.Unlock()
}

// Collect runs the scan and returns a fully populated report.
func (c *DependabotCollector) Collect(ctx context.Context, toolVersion string) (*model.DependabotReport, error) {
	started := c.now()

	organizations, err := c.resolveOrganizations(ctx)
	if err != nil {
		return nil, err
	}
	if len(organizations) == 0 {
		return nil, errors.New("no organizations to scan; pass --organization, --enterprise or --repository")
	}

	var repositories []model.DependabotRepo
	orgErrors := map[string]string{}

	for _, org := range organizations {
		orgRepos, err := c.collectOrganization(ctx, org)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			c.warn("organization %s could not be scanned: %v", org, err)
			orgErrors[org] = err.Error()
			continue
		}
		repositories = append(repositories, orgRepos...)
	}

	model.SortDependabotRepos(repositories)

	report := &model.DependabotReport{
		SchemaVersion: model.DependabotSchemaVersion,
		GeneratedAt:   c.now(),
		Tool:          model.ToolInfo{Name: "gh-ghas-audit", Version: toolVersion},
		Scope: model.Scope{
			Host:          c.client.Host(),
			Enterprise:    c.options.Enterprise,
			Organizations: organizations,
			Repository:    c.options.Repository,
		},
		Settings: model.DependabotSettings{
			SkipArchived:                 c.options.SkipArchived,
			SkipForks:                    c.options.SkipForks,
			Concurrency:                  c.options.Concurrency,
			Match:                        c.options.Match,
			Exclude:                      c.options.Exclude,
			Visibility:                   c.options.VisibilityFilter,
			ScanDepth:                    string(c.options.Depth),
			DependencyReviewCheckPattern: c.options.DependencyReviewCheckPattern,
		},
		Repositories: repositories,
		Summary:      model.BuildDependabotSummary(repositories),
	}

	report.Organizations = model.BuildDependabotOrgReports(repositories)
	for _, org := range organizations {
		if message, failed := orgErrors[org]; failed {
			report.Organizations = append(report.Organizations, model.OrgReport{Login: org, Error: message})
		}
	}
	sort.Slice(report.Organizations, func(i, j int) bool {
		return report.Organizations[i].Login < report.Organizations[j].Login
	})

	c.mu.Lock()
	report.Warnings = append([]string(nil), c.warnings...)
	c.mu.Unlock()

	stats := c.client.Stats()
	report.Stats = model.Stats{
		APIRequests:      int(stats.RESTRequests.Load()),
		GraphQLRequests:  int(stats.GraphQLRequests.Load()),
		CacheHits:        int(stats.CacheHits.Load()),
		RateLimitWaits:   int(stats.RateLimitWaits.Load()),
		DurationSeconds:  time.Since(started).Seconds(),
		RateLimitRemains: stats.RateLimitRemaining(),
		Incomplete:       len(report.Warnings) > 0 || anyDependabotRepoErrors(repositories),
	}

	return report, nil
}

func anyDependabotRepoErrors(repositories []model.DependabotRepo) bool {
	for _, repo := range repositories {
		if len(repo.Errors) > 0 {
			return true
		}
	}
	return false
}

// resolveOrganizations determines the organizations in scope, expanding an
// enterprise when one is supplied. This duplicates the equivalent logic in
// collector.go rather than sharing it, because that method is bound to the
// code scanning Collector's Options type.
func (c *DependabotCollector) resolveOrganizations(ctx context.Context) ([]string, error) {
	unique := map[string]bool{}
	var ordered []string
	add := func(name string) {
		name = strings.TrimSpace(name)
		key := strings.ToLower(name)
		if name == "" || unique[key] {
			return
		}
		unique[key] = true
		ordered = append(ordered, name)
	}

	if c.options.Repository != "" {
		org, _, ok := splitRepository(c.options.Repository)
		if !ok {
			return nil, fmt.Errorf("invalid repository %q; expected OWNER/REPO", c.options.Repository)
		}
		add(org)
		return ordered, nil
	}

	for _, org := range c.options.Organizations {
		add(org)
	}

	if c.options.Enterprise != "" {
		c.progress("Discovering organizations in enterprise %s", c.options.Enterprise)
		logins, err := c.enterpriseOrganizations(ctx, c.options.Enterprise)
		if err != nil {
			return nil, err
		}
		c.progress("Found %d organizations in enterprise %s", len(logins), c.options.Enterprise)
		for _, login := range logins {
			add(login)
		}
	}

	return ordered, nil
}

// enterpriseOrganizations lists every organization in an enterprise. It
// duplicates collector.go's method of the same name (bound to a different
// receiver type) rather than sharing it, to avoid any risk to the code
// scanning code path.
func (c *DependabotCollector) enterpriseOrganizations(ctx context.Context, slug string) ([]string, error) {
	const query = `query($slug:String!,$cursor:String){
  enterprise(slug:$slug){
    organizations(first:100,after:$cursor){
      pageInfo{hasNextPage endCursor}
      nodes{login}
    }
  }
}`

	var logins []string
	cursor := ""
	for {
		var response struct {
			Enterprise *struct {
				Organizations struct {
					PageInfo struct {
						HasNextPage bool   `json:"hasNextPage"`
						EndCursor   string `json:"endCursor"`
					} `json:"pageInfo"`
					Nodes []struct {
						Login string `json:"login"`
					} `json:"nodes"`
				} `json:"organizations"`
			} `json:"enterprise"`
		}

		variables := map[string]any{"slug": slug, "cursor": (*string)(nil)}
		if cursor != "" {
			variables["cursor"] = cursor
		}

		if err := c.client.GraphQL(ctx, query, variables, &response); err != nil {
			message := err.Error()
			if strings.Contains(message, "read:enterprise") || strings.Contains(message, "INSUFFICIENT_SCOPES") {
				return nil, fmt.Errorf(
					"listing organizations for enterprise %q requires an enterprise-scoped token: "+
						"run `gh auth refresh -h %s -s read:enterprise`, or pass --organization explicitly: %w",
					slug, c.client.Host(), err)
			}
			if strings.Contains(message, "Could not resolve to a Business") || strings.Contains(message, "NOT_FOUND") {
				return nil, fmt.Errorf(
					"enterprise %q was not found or is not visible to this token; "+
						"check the slug used in your enterprise URL, or pass --organization explicitly",
					slug)
			}
			return nil, fmt.Errorf("listing organizations for enterprise %q: %w", slug, err)
		}

		if response.Enterprise == nil {
			return nil, fmt.Errorf(
				"enterprise %q is not visible to this token. This is most often a missing scope: "+
					"run `gh auth refresh -h %s -s read:enterprise`. If a GH_TOKEN environment variable is set, "+
					"it overrides your stored credentials and may lack that scope. "+
					"Otherwise check the slug from your enterprise URL, or pass --organization explicitly",
				slug, c.client.Host())
		}

		for _, node := range response.Enterprise.Organizations.Nodes {
			if node.Login != "" {
				logins = append(logins, node.Login)
			}
		}

		if !response.Enterprise.Organizations.PageInfo.HasNextPage {
			break
		}
		cursor = response.Enterprise.Organizations.PageInfo.EndCursor
	}

	sort.Strings(logins)
	return logins, nil
}

// dependabotRepoSource is the minimal repository shape needed to decide scope
// and seed a DependabotRepo, gathered without the language enumeration
// code scanning's inventory needs.
type dependabotRepoSource struct {
	Name          string
	FullName      string
	URL           string
	IsArchived    bool
	IsFork        bool
	Visibility    string
	DefaultBranch string
	PushedAt      *time.Time
}

// collectOrganization scans a single organization.
func (c *DependabotCollector) collectOrganization(ctx context.Context, org string) ([]model.DependabotRepo, error) {
	sources, err := c.listOrganizationRepositories(ctx, org)
	if err != nil {
		return nil, err
	}

	eligible := make([]dependabotRepoSource, 0, len(sources))
	for _, source := range sources {
		if c.skipRepository(source) {
			continue
		}
		eligible = append(eligible, source)
	}

	workers := c.options.Concurrency
	if workers > len(eligible) {
		workers = len(eligible)
	}
	if workers < 1 {
		workers = 1
	}
	c.progress("Scanning %s: %d of %d repositories in scope (up to %d concurrently)", org, len(eligible), len(sources), workers)

	return c.scanRepositories(ctx, org, eligible)
}

func (c *DependabotCollector) skipRepository(source dependabotRepoSource) bool {
	if c.options.SkipArchived && source.IsArchived {
		return true
	}
	if c.options.SkipForks && source.IsFork {
		return true
	}
	if len(c.options.VisibilityFilter) > 0 && !matchesAny(source.Visibility, c.options.VisibilityFilter) {
		return true
	}
	if len(c.options.Match) > 0 && !matchesAny(source.Name, c.options.Match) {
		return true
	}
	if len(c.options.Exclude) > 0 && matchesAny(source.Name, c.options.Exclude) {
		return true
	}
	return false
}

// listOrganizationRepositories enumerates an organization's repositories with
// just the fields the Dependabot collector needs. When --repository scopes
// the run to a single repository, GraphQL enumeration is skipped entirely.
func (c *DependabotCollector) listOrganizationRepositories(ctx context.Context, org string) ([]dependabotRepoSource, error) {
	if c.options.Repository != "" {
		_, name, ok := splitRepository(c.options.Repository)
		if !ok {
			return nil, fmt.Errorf("invalid repository %q; expected OWNER/REPO", c.options.Repository)
		}
		source, err := c.getRepository(ctx, org, name)
		if err != nil {
			return nil, err
		}
		return []dependabotRepoSource{source}, nil
	}

	const query = `query($org:String!,$cursor:String){
  organization(login:$org){
    repositories(first:100,after:$cursor,orderBy:{field:PUSHED_AT,direction:DESC}){
      pageInfo{hasNextPage endCursor}
      nodes{
        name
        url
        isArchived
        isFork
        visibility
        pushedAt
        defaultBranchRef{name}
      }
    }
  }
}`

	var repositories []dependabotRepoSource
	cursor := ""
	for {
		var response struct {
			Organization *struct {
				Repositories struct {
					PageInfo struct {
						HasNextPage bool   `json:"hasNextPage"`
						EndCursor   string `json:"endCursor"`
					} `json:"pageInfo"`
					Nodes []struct {
						Name             string  `json:"name"`
						URL              string  `json:"url"`
						IsArchived       bool    `json:"isArchived"`
						IsFork           bool    `json:"isFork"`
						Visibility       string  `json:"visibility"`
						PushedAt         *string `json:"pushedAt"`
						DefaultBranchRef *struct {
							Name string `json:"name"`
						} `json:"defaultBranchRef"`
					} `json:"nodes"`
				} `json:"repositories"`
			} `json:"organization"`
		}

		variables := map[string]any{"org": org, "cursor": (*string)(nil)}
		if cursor != "" {
			variables["cursor"] = cursor
		}

		if err := c.client.GraphQL(ctx, query, variables, &response); err != nil {
			return nil, fmt.Errorf("listing repositories for %s: %w", org, err)
		}
		if response.Organization == nil {
			return nil, fmt.Errorf("organization %q was not found or is not visible to this token", org)
		}

		for _, node := range response.Organization.Repositories.Nodes {
			source := dependabotRepoSource{
				Name:       node.Name,
				FullName:   org + "/" + node.Name,
				URL:        node.URL,
				IsArchived: node.IsArchived,
				IsFork:     node.IsFork,
				Visibility: strings.ToUpper(node.Visibility),
			}
			if node.DefaultBranchRef != nil {
				source.DefaultBranch = node.DefaultBranchRef.Name
			}
			if node.PushedAt != nil {
				if parsed, err := time.Parse(time.RFC3339, *node.PushedAt); err == nil {
					source.PushedAt = &parsed
				}
			}
			repositories = append(repositories, source)
		}

		if !response.Organization.Repositories.PageInfo.HasNextPage {
			break
		}
		cursor = response.Organization.Repositories.PageInfo.EndCursor
	}

	return repositories, nil
}

// getRepository fetches a single repository via REST, used for --repository
// scope where GraphQL enumeration is unnecessary.
func (c *DependabotCollector) getRepository(ctx context.Context, org, name string) (dependabotRepoSource, error) {
	var rest dependabotRestRepository
	if err := c.client.GetJSON(ctx, fmt.Sprintf("repos/%s/%s", url.PathEscape(org), url.PathEscape(name)), &rest); err != nil {
		return dependabotRepoSource{}, fmt.Errorf("reading repository %s/%s: %w", org, name, err)
	}
	source := dependabotRepoSource{
		Name:          rest.Name,
		FullName:      rest.FullName,
		URL:           rest.HTMLURL,
		IsArchived:    rest.Archived,
		IsFork:        rest.Fork,
		Visibility:    strings.ToUpper(rest.Visibility),
		DefaultBranch: rest.DefaultBranch,
		PushedAt:      rest.PushedAt,
	}
	return source, nil
}

// scanRepositories collects Dependabot evidence for each repository
// concurrently, mirroring code scanning's worker pool.
func (c *DependabotCollector) scanRepositories(
	ctx context.Context,
	org string,
	sources []dependabotRepoSource,
) ([]model.DependabotRepo, error) {
	results := make([]model.DependabotRepo, len(sources))

	workers := c.options.Concurrency
	if workers > len(sources) {
		workers = len(sources)
	}
	if workers < 1 {
		workers = 1
	}

	jobs := make(chan int)
	var wg sync.WaitGroup
	var completed int
	var progressMu sync.Mutex

	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				if ctx.Err() != nil {
					return
				}
				source := sources[index]
				started := time.Now()
				repo := c.collectRepository(ctx, org, source)
				elapsed := time.Since(started)
				results[index] = repo

				progressMu.Lock()
				if c.options.OnRepository != nil {
					c.options.OnRepository(repo)
				}
				completed++
				if c.options.Verbose {
					c.progress("  %s/%s: %s (%d/%d, %s)", org, source.Name, repo.Status.Overall, completed, len(sources), elapsed.Round(time.Millisecond*100))
				} else if completed%25 == 0 || completed == len(sources) {
					c.progress("  %s: %d/%d repositories inspected", org, completed, len(sources))
				}
				progressMu.Unlock()
			}
		}()
	}

	for index := range sources {
		select {
		case jobs <- index:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return nil, ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	return results, nil
}

// collectRepository gathers all Dependabot/SCA evidence for one repository.
func (c *DependabotCollector) collectRepository(ctx context.Context, org string, source dependabotRepoSource) model.DependabotRepo {
	repo := model.DependabotRepo{
		Organization:                  org,
		Name:                          source.Name,
		FullName:                      source.FullName,
		URL:                           source.URL,
		Visibility:                    source.Visibility,
		Archived:                      source.IsArchived,
		Fork:                          source.IsFork,
		DefaultBranch:                 source.DefaultBranch,
		PushedAt:                      timestampPtr(source.PushedAt),
		TemporarySecurityAdvisoryFork: isTemporarySecurityAdvisoryForkName(source.Name),
	}
	if repo.PushedAt != nil {
		repo.LastActivityAt = repo.PushedAt
	}

	c.collectSecurityAndAnalysis(ctx, org, source.Name, &repo)
	c.collectVersionUpdates(ctx, org, source.Name, &repo)

	if c.options.Depth == DepthConfig {
		repo.Status.DependencyGraph = model.FeatureNotEvaluated
		repo.Status.DependencyGraphCoverage = model.GraphCoverageNotEvaluated
		repo.Status.DependabotAlerts = model.FeatureNotEvaluated
		repo.Status.PullRequestHealth = model.PRHealthNotEvaluated
		repo.Status.DependencyReview = model.DependencyReviewNotEvaluated
		repo.Status.Incomplete = len(repo.Errors) > 0
		model.ClassifyDependabot(&repo.Status)
		return repo
	}

	c.collectDependencyGraph(ctx, org, source.Name, &repo)
	c.collectAlerts(ctx, org, source.Name, &repo)

	// Dependabot alerts are built on top of the dependency graph and cannot
	// be enabled without it (see "Check if vulnerability alerts are enabled
	// for a repository" in the REST docs). An enabled alerts feature is
	// therefore authoritative evidence the graph is on, even when the
	// GraphQL manifests query above could not be evaluated (for example a
	// rate limit that outlasted the retry budget) or found no manifests.
	if repo.Status.DependabotAlerts == model.FeatureEnabled && repo.Status.DependencyGraph != model.FeatureEnabled {
		repo.Status.DependencyGraph = model.FeatureEnabled
	}

	authoritativePaused := c.collectAutomatedSecurityFixes(ctx, org, source.Name, &repo)
	c.collectPullRequests(ctx, org, source.Name, &repo, authoritativePaused)

	if c.options.Depth == DepthDiagnostics {
		c.collectDependencyReview(ctx, org, source.Name, &repo)
	} else {
		repo.Status.DependencyReview = model.DependencyReviewNotEvaluated
	}

	// A collection failure recorded anywhere above (dependency graph,
	// alerts, pull requests, dependency review, and so on) must prevent a
	// confident healthy verdict: without this, dependabotClassify's
	// Incomplete safety net never engages, since nothing else in this
	// collector ever sets Status.Incomplete.
	repo.Status.Incomplete = len(repo.Errors) > 0

	model.ClassifyDependabot(&repo.Status)
	return repo
}

func timestampPtr(t *time.Time) *model.Timestamp {
	if t == nil {
		return nil
	}
	converted := model.Timestamp(*t)
	return &converted
}

// collectSecurityAndAnalysis reads the repository's security_and_analysis
// block, which is only visible to repository admins, owners or security
// managers. Its absence must be read as "unknown", never "disabled".
func (c *DependabotCollector) collectSecurityAndAnalysis(ctx context.Context, org, name string, repo *model.DependabotRepo) {
	var rest dependabotRestRepository
	path := fmt.Sprintf("repos/%s/%s", url.PathEscape(org), url.PathEscape(name))
	if err := c.client.GetJSON(ctx, path, &rest); err != nil {
		repo.Errors = append(repo.Errors, fmt.Sprintf("repository details: %v", err))
		repo.Status.DependabotSecurityUpdates = model.FeatureUnknown
		return
	}

	if rest.SecurityAndAnalysis == nil || rest.SecurityAndAnalysis.DependabotSecurityUpdates == nil {
		repo.Status.DependabotSecurityUpdates = model.FeatureUnknown
		return
	}
	switch strings.ToLower(rest.SecurityAndAnalysis.DependabotSecurityUpdates.Status) {
	case "enabled":
		repo.Status.DependabotSecurityUpdates = model.FeatureEnabled
	case "disabled":
		repo.Status.DependabotSecurityUpdates = model.FeatureDisabled
	default:
		repo.Status.DependabotSecurityUpdates = model.FeatureUnknown
	}
}

// collectAutomatedSecurityFixes reads the "Check if Dependabot security
// updates are enabled for a repository" endpoint
// (repos/{owner}/{repo}/automated-security-fixes), which returns a JSON body
// with "enabled" and "paused" booleans regardless of caller permission level.
// This is a stronger corroboration signal than security_and_analysis (which
// is only visible to admins/owners/security managers) for DependabotSecurityUpdates,
// and it is the authoritative source for whether GitHub has paused all
// automated Dependabot activity for prolonged inactivity: unlike the
// "dependabot-paused" pull request label, it is populated even when a
// repository has zero open Dependabot pull requests to carry that label.
// Any error from this call is treated as best-effort unavailable: nothing is
// changed, it is not recorded as a collection error, and the caller should
// fall back to the pull request label. The returned pointer is nil when the
// call failed, and otherwise points at the authoritative paused value.
func (c *DependabotCollector) collectAutomatedSecurityFixes(ctx context.Context, org, name string, repo *model.DependabotRepo) *bool {
	var status struct {
		Enabled bool `json:"enabled"`
		Paused  bool `json:"paused"`
	}
	path := fmt.Sprintf("repos/%s/%s/automated-security-fixes", url.PathEscape(org), url.PathEscape(name))
	if err := c.client.GetJSON(ctx, path, &status); err != nil {
		return nil
	}
	if repo.Status.DependabotSecurityUpdates == model.FeatureUnknown {
		if status.Enabled {
			repo.Status.DependabotSecurityUpdates = model.FeatureEnabled
		} else {
			repo.Status.DependabotSecurityUpdates = model.FeatureDisabled
		}
	}
	if status.Paused {
		repo.Status.VersionUpdates = model.VersionUpdatesPausedInactivity
	}
	return &status.Paused
}

// collectVersionUpdates reads and parses .github/dependabot.yml.
func (c *DependabotCollector) collectVersionUpdates(ctx context.Context, org, name string, repo *model.DependabotRepo) {
	for _, candidate := range []string{".github/dependabot.yml", ".github/dependabot.yaml"} {
		content, err := c.fetchFileContent(ctx, org, name, candidate)
		if err != nil {
			if isNotFoundError(err) {
				continue
			}
			repo.Errors = append(repo.Errors, fmt.Sprintf("dependabot.yml: %v", err))
			repo.Status.VersionUpdates = model.VersionUpdatesUnknown
			return
		}

		var parsed dependabotYAML
		if yamlErr := yaml.Unmarshal(content, &parsed); yamlErr != nil {
			repo.VersionUpdates.ConfigPath = candidate
			repo.VersionUpdates.ParseError = yamlErr.Error()
			repo.Status.VersionUpdates = model.VersionUpdatesParseError
			return
		}

		repo.VersionUpdates.ConfigPath = candidate
		ecosystems := map[string]bool{}
		targetBranches := map[string]bool{}
		registries := make([]string, 0, len(parsed.Registries))
		for registryName := range parsed.Registries {
			registries = append(registries, registryName)
		}
		sort.Strings(registries)
		repo.VersionUpdates.RegistriesConfigured = registries

		const defaultLimitPerBlock = 5
		ecosystemLimits := map[string]int{}
		for _, update := range parsed.Updates {
			if update.PackageEcosystem != "" {
				ecosystems[update.PackageEcosystem] = true
				limit := defaultLimitPerBlock
				if update.OpenPullRequestsLimit != nil {
					limit = *update.OpenPullRequestsLimit
				}
				ecosystemLimits[update.PackageEcosystem] += limit
			}
			if update.TargetBranch != "" {
				targetBranches[update.TargetBranch] = true
			}
		}
		repo.VersionUpdates.Ecosystems = sortedKeys(ecosystems)
		repo.VersionUpdates.TargetBranches = sortedKeys(targetBranches)
		repo.VersionUpdates.UncoveredEcosystems = uncoveredEcosystems(repo.VersionUpdates.Ecosystems)
		if len(ecosystemLimits) > 0 {
			repo.VersionUpdates.EcosystemLimits = ecosystemLimits
		}

		repo.Status.VersionUpdates = model.VersionUpdatesConfigured
		return
	}

	repo.Status.VersionUpdates = model.VersionUpdatesNotConfigured
}

// graphEcosystems are the dependabot.yml package-ecosystem values that do
// have dependency-graph/Dependabot-alert coverage. This is not the same set
// as the GraphQL DependencyGraphEcosystem enum: Gradle dependencies are
// tracked by the dependency graph, but under that enum's MAVEN value (there
// is no distinct GRADLE entry in the dependency graph's own ecosystem
// classification), while dependabot.yml's package-ecosystem: gradle is a
// distinct, valid configuration value. Both must be listed here so a
// gradle-configured update block is not misreported as having no
// dependency-graph/alert coverage at all.
var graphEcosystems = map[string]bool{
	"github-actions": true,
	"composer":       true,
	"gomod":          true,
	"maven":          true,
	"gradle":         true,
	"npm":            true,
	"nuget":          true,
	"pip":            true,
	"pub":            true,
	"bundler":        true,
	"cargo":          true,
	"swift":          true,
}

func uncoveredEcosystems(configured []string) []string {
	var uncovered []string
	for _, ecosystem := range configured {
		if !graphEcosystems[strings.ToLower(ecosystem)] {
			uncovered = append(uncovered, ecosystem)
		}
	}
	return uncovered
}

func sortedKeys(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// fetchFileContent reads a single file's decoded content via the Contents
// API.
func (c *DependabotCollector) fetchFileContent(ctx context.Context, org, name, filePath string) ([]byte, error) {
	var file contentsFile
	apiPath := fmt.Sprintf("repos/%s/%s/contents/%s", url.PathEscape(org), url.PathEscape(name), filePath)
	if err := c.client.GetJSON(ctx, apiPath, &file); err != nil {
		return nil, err
	}
	if file.Type != "" && file.Type != "file" {
		return nil, fmt.Errorf("%s is not a file", filePath)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(file.Content, "\n", ""))
	if err != nil {
		return nil, fmt.Errorf("decoding %s: %w", filePath, err)
	}
	return decoded, nil
}

func isNotFoundError(err error) bool {
	return strings.Contains(err.Error(), "404") || strings.Contains(strings.ToLower(err.Error()), "not found")
}

// temporarySecurityAdvisoryForkNamePattern matches GitHub's documented naming
// convention for a temporary private fork automatically created to draft a
// fix for a repository security advisory: the source repository's name,
// followed by "-ghsa-" and the advisory's GHSA identifier suffix, three
// groups of four base32-like characters each (for example
// "spdx-examples-ghsa-4xcm-h78r-r3ww"). There is no dedicated REST or
// GraphQL field marking a repository as one of these forks (a known,
// long-standing API gap); this name suffix is GitHub's own documented,
// deterministic identifier for them, and is a far more specific signal than
// any repository property such as visibility or a non-empty
// temp_clone_token, both of which are also present on every ordinary
// private/internal repository and so would misidentify nearly all of them.
var temporarySecurityAdvisoryForkNamePattern = regexp.MustCompile(`(?i)-ghsa-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$`)

// isTemporarySecurityAdvisoryForkName reports whether a repository name
// matches temporarySecurityAdvisoryForkNamePattern.
func isTemporarySecurityAdvisoryForkName(name string) bool {
	return temporarySecurityAdvisoryForkNamePattern.MatchString(name)
}

// buildTimeResolutionManifest reports whether a manifest filename belongs to
// an ecosystem where GitHub's dependency graph cannot see transitive
// dependencies from a static parse of the manifest alone: Maven (pom.xml),
// Gradle (build.gradle/build.gradle.kts), and NuGet (.csproj/.vbproj/
// packages.config, absent a packages.lock.json). These ecosystems need
// either a lockfile or a build-time dependency-submission workflow (for
// example the Maven, Gradle, or Component Detection dependency-submission
// actions) before the graph reflects anything beyond the packages an
// unresolved manifest lists directly.
func buildTimeResolutionManifest(filename string) bool {
	base := strings.ToLower(path.Base(filename))
	switch {
	case base == "pom.xml":
		return true
	case strings.HasSuffix(base, "build.gradle") || strings.HasSuffix(base, "build.gradle.kts"):
		return true
	case strings.HasSuffix(base, ".csproj") || strings.HasSuffix(base, ".vbproj") || base == "packages.config":
		return true
	default:
		return false
	}
}

// manifestEcosystem gives a best-effort, display-only ecosystem label for a
// manifest filename.
func manifestEcosystem(filename string) string {
	base := strings.ToLower(path.Base(filename))
	switch {
	case base == "pom.xml":
		return "maven"
	case strings.HasSuffix(base, "build.gradle") || strings.HasSuffix(base, "build.gradle.kts"):
		return "gradle"
	case base == "package.json" || base == "package-lock.json" || base == "yarn.lock" || base == "pnpm-lock.yaml":
		return "npm"
	case base == "go.mod" || base == "go.sum":
		return "go"
	case base == "requirements.txt" || base == "pipfile" || base == "pipfile.lock" || base == "pyproject.toml":
		return "pip"
	case base == "gemfile" || base == "gemfile.lock":
		return "rubygems"
	case base == "composer.json" || base == "composer.lock":
		return "composer"
	case base == "cargo.toml" || base == "cargo.lock":
		return "cargo"
	case strings.HasSuffix(base, ".csproj") || base == "packages.config":
		return "nuget"
	default:
		return ""
	}
}

// collectDependencyGraph reads dependencyGraphManifests via GraphQL and
// derives manifest-level evidence, including the transitive-coverage gap for
// Maven/Gradle manifests.
func (c *DependabotCollector) collectDependencyGraph(ctx context.Context, org, name string, repo *model.DependabotRepo) {
	const query = `query($owner:String!,$name:String!,$cursor:String){
  repository(owner:$owner,name:$name){
    dependencyGraphManifests(first:20,after:$cursor){
      totalCount
      pageInfo{hasNextPage endCursor}
      nodes{
        id
        filename
        parseable
        exceedsMaxSize
        dependenciesCount
        dependencies(first:100){
          pageInfo{hasNextPage endCursor}
          nodes{relationship}
        }
      }
    }
  }
}`

	var nodes []dependencyGraphManifestNode
	total := 0
	cursor := ""
	for {
		var response dependencyGraphManifestsResponse
		variables := map[string]any{"owner": org, "name": name, "cursor": (*string)(nil)}
		if cursor != "" {
			variables["cursor"] = cursor
		}
		if err := c.client.GraphQL(ctx, query, variables, &response); err != nil {
			repo.Errors = append(repo.Errors, fmt.Sprintf("dependency graph manifests: %v", err))
			repo.Status.DependencyGraph = model.FeatureUnknown
			repo.Status.DependencyGraphCoverage = model.GraphCoverageUnknown
			return
		}
		if response.Repository == nil {
			repo.Errors = append(repo.Errors, "dependency graph manifests: repository not found")
			repo.Status.DependencyGraph = model.FeatureUnknown
			repo.Status.DependencyGraphCoverage = model.GraphCoverageUnknown
			return
		}
		total = response.Repository.DependencyGraphManifests.TotalCount
		nodes = append(nodes, response.Repository.DependencyGraphManifests.Nodes...)
		if !response.Repository.DependencyGraphManifests.PageInfo.HasNextPage {
			break
		}
		cursor = response.Repository.DependencyGraphManifests.PageInfo.EndCursor
	}

	repo.DependencyGraph.Evaluated = true
	repo.DependencyGraph.TotalManifests = total

	const inspectedDependenciesPerManifest = 100
	ecosystems := map[string]bool{}
	var unparseable, oversized, missingTransitive []string
	for _, node := range nodes {
		if ecosystem := manifestEcosystem(node.Filename); ecosystem != "" {
			ecosystems[ecosystem] = true
		}
		if !node.Parseable {
			unparseable = append(unparseable, node.Filename)
		}
		if node.ExceedsMaxSize {
			oversized = append(oversized, node.Filename)
		}
		if buildTimeResolutionManifest(node.Filename) && node.DependenciesCount > 0 {
			hasTransitive := false
			for _, dependency := range node.Dependencies.Nodes {
				if strings.EqualFold(dependency.Relationship, "transitive") {
					hasTransitive = true
					break
				}
			}
			if hasTransitive {
				continue
			}
			if node.DependenciesCount > len(node.Dependencies.Nodes) && len(node.Dependencies.Nodes) >= inspectedDependenciesPerManifest {
				// Only the first inspectedDependenciesPerManifest
				// dependencies were inspected so far, and none of them were
				// transitive, but the manifest has more dependencies than
				// that. The GraphQL schema's dependencies connection
				// actually supports full cursor pagination (confirmed via
				// the public schema and live testing), so rather than just
				// flagging this as inconclusive, page through the rest of
				// this specific manifest's dependencies looking for a
				// transitive one. This is bounded to only the rare manifest
				// that needs it (most manifests never reach this branch at
				// all), not a blanket per-repository cost.
				resolved, foundTransitive, err := c.manifestHasTransitiveDependencyBeyondSample(
					ctx, node.ID, node.Dependencies.PageInfo.EndCursor, node.Dependencies.PageInfo.HasNextPage)
				if err != nil {
					repo.Errors = append(repo.Errors, fmt.Sprintf(
						"dependency graph manifests: %s: could not inspect dependencies beyond the first %d: %v",
						node.Filename, len(node.Dependencies.Nodes), err))
					continue
				}
				if foundTransitive {
					continue
				}
				if !resolved {
					// The safety cap was hit before exhausting every page;
					// a transitive dependency could still exist beyond the
					// (now much larger) inspected sample. Reporting a
					// confirmed gap here would still risk a false positive,
					// so this is recorded as an inconclusive collection
					// note instead.
					repo.Errors = append(repo.Errors, fmt.Sprintf(
						"dependency graph manifests: %s has %d dependencies; inspection stopped after the pagination "+
							"safety cap with no transitive dependency found yet, so transitive coverage is unknown, not confirmed missing",
						node.Filename, node.DependenciesCount))
					continue
				}
				// Every dependency was inspected (pagination fully
				// exhausted) and none was transitive: this is now a
				// confirmed gap, not a sampling artifact.
			}
			missingTransitive = append(missingTransitive, node.Filename)
		}
	}
	repo.DependencyGraph.Ecosystems = sortedKeys(ecosystems)
	repo.DependencyGraph.UnparseableManifests = unparseable
	repo.DependencyGraph.OversizedManifests = oversized
	repo.DependencyGraph.ManifestsMissingTransitive = missingTransitive
	if len(unparseable) > 0 {
		repo.Errors = append(repo.Errors, fmt.Sprintf(
			"dependency graph manifests: %d manifest(s) could not be parsed and contribute no dependency evidence: %s",
			len(unparseable), strings.Join(unparseable, ", ")))
	}
	if len(oversized) > 0 {
		repo.Errors = append(repo.Errors, fmt.Sprintf(
			"dependency graph manifests: %d manifest(s) exceeded the graph's maximum size and were only partially processed: %s",
			len(oversized), strings.Join(oversized, ", ")))
	}

	// The dependency graph has no simple per-repository "enabled" boolean.
	// Manifest evidence, even zero manifests, means the query executed
	// successfully against a repository where the graph is reachable; that is
	// the best available signal short of an explicit toggle.
	if total > 0 || len(nodes) > 0 {
		repo.Status.DependencyGraph = model.FeatureEnabled
	} else {
		repo.Status.DependencyGraph = model.FeatureNotSet
	}

	hasBuildTimeManifest := false
	for _, node := range nodes {
		if buildTimeResolutionManifest(node.Filename) {
			hasBuildTimeManifest = true
			break
		}
	}

	switch {
	case len(missingTransitive) > 0:
		// A gap was found. Check whether known dependency-submission
		// workflows already mitigate it before flagging the repository as
		// degraded. Mitigation is ecosystem-scoped: a detected Go submission
		// action, for example, must not be treated as closing an unrelated
		// NuGet manifest gap. Coverage is only "mitigated" when every
		// ecosystem among the missing-transitive manifests is covered by at
		// least one matched detector.
		matches := c.detectAutoSubmission(ctx, org, name)
		repo.DependencyGraph.AutoSubmissionDetected = len(matches) > 0
		repo.DependencyGraph.AutoSubmissionAction = joinDetectorIDs(matches)
		if allEcosystemsCovered(missingTransitive, matches) {
			repo.Status.DependencyGraphCoverage = model.GraphCoverageMitigated
		} else {
			repo.Status.DependencyGraphCoverage = model.GraphCoveragePartial
		}
	case hasBuildTimeManifest:
		// No gap: every build-time-resolution manifest already shows
		// transitive dependencies. Still check for a known
		// dependency-submission workflow so AutoSubmissionDetected/Action
		// positively confirm what is making that coverage complete, rather
		// than staying blank simply because there was no gap left to
		// mitigate. This is the common case for a repository that already
		// has an auto-submission workflow configured and working.
		matches := c.detectAutoSubmission(ctx, org, name)
		detected := len(matches) > 0
		action := joinDetectorIDs(matches)
		if !detected {
			// A workflow file is not the only way coverage gets fixed:
			// GitHub's native "Automatic Dependency Submission" toggle (no
			// workflow file at all, Settings > Security & quality) also
			// produces transitive data, and detectAutoSubmission's
			// workflow-content scan cannot see it. Only attempted here, in
			// the no-gap case: the SBOM's creators list is repo-wide, not
			// per-manifest, so a real per-manifest gap must never be
			// silently reclassified as mitigated on its evidence alone (a
			// repository can have this toggle enabled and still leave one
			// project in a monorepo unresolved).
			detected, action = c.detectAutoSubmissionFromSBOM(ctx, org, name)
		}
		repo.DependencyGraph.AutoSubmissionDetected = detected
		repo.DependencyGraph.AutoSubmissionAction = action
		repo.Status.DependencyGraphCoverage = model.GraphCoverageComplete
	default:
		repo.Status.DependencyGraphCoverage = model.GraphCoverageNotApplicable
	}
}

// maxManifestDependencyPaginationPages bounds how many additional
// dependencies(first:100) pages manifestHasTransitiveDependencyBeyondSample
// will fetch for a single manifest beyond the initial sample already read
// by collectDependencyGraph's bulk query. This is deliberately much more
// generous than the per-repo alert (3 pages) and vulnerability-alert-
// linkage (5 pages) caps elsewhere in this collector: those apply to every
// single repository that has any alerts at all, so their cost multiplies
// across an entire org scan, which is what caused a real hang earlier.
// This cap instead only ever applies per ambiguous manifest — one that is
// both a build-time-resolution ecosystem (Maven/Gradle/NuGet; npm, pip,
// etc. never reach this code path at all, since their relationships are
// already known from a static lockfile parse) and had zero transitive
// dependencies in its first 100, which a live scan of 100 real repositories
// never produced even once (the largest manifest found had 62 total
// dependencies). It exists only as a safety net against a pathological
// manifest or a cursor that never terminates, not as a practically-expected
// limit: GitHub returns each manifest's dependencies in a stable order
// (alphabetical by package name, confirmed via live testing), so once a
// manifest is actually resolved, a transitive dependency is virtually
// certain to appear within the first page or two regardless of total
// size, thanks to manifestHasTransitiveDependencyBeyondSample's early exit
// on the first match. 50 pages (5,100 total dependencies inspected,
// combined with the initial sample) comfortably covers even a very large
// genuinely-unresolved manifest without the open-ended cost an unbounded
// loop would risk.
const maxManifestDependencyPaginationPages = 50

// manifestHasTransitiveDependencyBeyondSample pages through a single
// manifest's remaining dependencies (via the Node interface, since
// DependencyGraphManifest implements it) looking for any transitive
// relationship not already seen in the initial dependencies(first:100)
// sample read by collectDependencyGraph. It stops as soon as one is found.
// resolved reports whether every remaining dependency was inspected
// (pagination reached hasNextPage=false) before the safety cap; when
// resolved is false, the manifest's remaining dependencies were only
// partially inspected and the result is inconclusive, not a confirmed
// absence of transitive coverage.
func (c *DependabotCollector) manifestHasTransitiveDependencyBeyondSample(
	ctx context.Context, manifestID, cursor string, hasNextPage bool,
) (resolved bool, foundTransitive bool, err error) {
	const query = `query($id:ID!,$cursor:String){
  node(id:$id){
    ... on DependencyGraphManifest {
      dependencies(first:100,after:$cursor){
        pageInfo{hasNextPage endCursor}
        nodes{relationship}
      }
    }
  }
}`
	for page := 0; hasNextPage; page++ {
		if page >= maxManifestDependencyPaginationPages {
			return false, false, nil
		}
		var response manifestDependenciesPageResponse
		variables := map[string]any{"id": manifestID, "cursor": (*string)(nil)}
		if cursor != "" {
			variables["cursor"] = cursor
		}
		if err := c.client.GraphQL(ctx, query, variables, &response); err != nil {
			return false, false, err
		}
		if response.Node == nil {
			// The manifest node could no longer be resolved (for example,
			// deleted between the initial query and this follow-up); treat
			// this the same as any other collection failure rather than
			// silently asserting a confirmed gap.
			return false, false, fmt.Errorf("manifest node not found")
		}
		for _, dependency := range response.Node.Dependencies.Nodes {
			if strings.EqualFold(dependency.Relationship, "transitive") {
				return true, true, nil
			}
		}
		hasNextPage = response.Node.Dependencies.PageInfo.HasNextPage
		cursor = response.Node.Dependencies.PageInfo.EndCursor
	}
	return true, false, nil
}

// joinDetectorIDs renders the IDs of matched detectors for display in
// AutoSubmissionAction, joining multiple matches so none are silently
// dropped.
func joinDetectorIDs(matches []autoSubmissionDetector) string {
	if len(matches) == 0 {
		return ""
	}
	ids := make([]string, len(matches))
	for i, m := range matches {
		ids[i] = m.ID
	}
	return strings.Join(ids, ", ")
}

// allEcosystemsCovered reports whether every manifest filename in
// missingTransitive has its manifestEcosystem covered by at least one of the
// matched detectors (either an ecosystem-specific match, or any generic,
// ecosystem-agnostic match).
func allEcosystemsCovered(missingTransitive []string, matches []autoSubmissionDetector) bool {
	if len(matches) == 0 {
		return false
	}
	for _, filename := range missingTransitive {
		ecosystem := manifestEcosystem(filename)
		covered := false
		for _, m := range matches {
			if m.coversEcosystem(ecosystem) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// detectAutoSubmission scans the repository's Actions workflow files for
// known build-time dependency submission actions or steps. This is best
// effort: it is only run once a Maven/Gradle/NuGet/etc. direct-only manifest
// gap has already been found, which keeps the extra API calls proportional
// to the problem. It returns every knownAutoSubmissionDetectors entry that
// matched (deduplicated by ID, not just the first one found), so the caller
// can confirm ecosystem-scoped coverage rather than assuming one match
// mitigates every gap; a bare reference to the dependency submission API's
// REST endpoint, with no recognized Action alongside it, is reported
// distinctly as a custom submitter (see customAutoSubmissionActionID).
// Comment-only lines (trimmed content starting with "#") are stripped
// before matching, so a marker referenced only inside a disabled,
// commented-out workflow step is not mistaken for active mitigation.
func (c *DependabotCollector) detectAutoSubmission(ctx context.Context, org, name string) []autoSubmissionDetector {
	var entries []contentsEntry
	listPath := fmt.Sprintf("repos/%s/%s/contents/.github/workflows", url.PathEscape(org), url.PathEscape(name))
	if err := c.client.GetJSON(ctx, listPath, &entries); err != nil {
		return nil
	}

	const maxWorkflowsInspected = 20
	inspected := 0
	foundCustom := false
	matched := map[string]autoSubmissionDetector{}
	for _, entry := range entries {
		if entry.Type != "file" {
			continue
		}
		lower := strings.ToLower(entry.Name)
		if !strings.HasSuffix(lower, ".yml") && !strings.HasSuffix(lower, ".yaml") {
			continue
		}
		if inspected >= maxWorkflowsInspected {
			break
		}
		inspected++

		content, err := c.fetchFileContent(ctx, org, name, entry.Path)
		if err != nil {
			continue
		}
		lowerContent := strings.ToLower(stripYAMLCommentLines(string(content)))
		for _, detector := range knownAutoSubmissionDetectors {
			if !strings.Contains(lowerContent, detector.Marker) {
				continue
			}
			if isGenericAutoSubmissionMarker(detector.Marker) && genericMarkerSubsumedBySpecificMatch(lowerContent, detector.Marker) {
				// Several specific action slugs (for example
				// "advanced-security/maven-dependency-submission-action" or
				// "gradle/actions/dependency-submission") contain a generic
				// marker like "dependency-submission-action" or
				// "actions/dependency-submission" as a literal substring of
				// their own name. The generic markers exist only to catch
				// an unrecognized fork or rename; they must not also
				// register as a second, ecosystem-agnostic "any" match
				// alongside an already-identified specific action, which
				// would let that specific action's real ecosystem scope be
				// bypassed.
				continue
			}
			matched[detector.ID] = detector
		}
		if strings.Contains(lowerContent, customDependencySubmissionMarker) {
			foundCustom = true
		}
	}
	var results []autoSubmissionDetector
	for _, detector := range matched {
		results = append(results, detector)
	}
	if foundCustom {
		results = append(results, autoSubmissionDetector{ID: customAutoSubmissionActionID})
	}
	sort.Slice(results, func(i, j int) bool { return results[i].ID < results[j].ID })
	return results
}

// stripYAMLCommentLines removes every line whose trimmed content begins with
// "#" from content, so a marker referenced only in a disabled, commented-out
// workflow step is not treated as live evidence of auto-submission.
func stripYAMLCommentLines(content string) string {
	lines := strings.Split(content, "\n")
	kept := lines[:0]
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// sbomBaselineCreators are the tool entries GitHub's SBOM export always
// includes, whether or not any build-time submission ever ran: the SBOM
// generator library itself, and a generic marker for the dependency graph
// service. Any additional creator entry beyond these names the specific
// mechanism (a custom Action, a language plugin, or GitHub's own
// no-workflow-file "Automatic Dependency Submission" toggle) that populated
// the graph with more than a static manifest parse.
var sbomBaselineCreators = map[string]bool{
	"github.com-dependency-graph": true,
}

// detectAutoSubmissionFromSBOM reads GET
// /repos/{owner}/{repo}/dependency-graph/sbom and inspects
// sbom.creationInfo.creators for a tool beyond the baseline ones GitHub
// always lists. This is the only way to detect GitHub's native "Automatic
// Dependency Submission" repository toggle: unlike a custom dependency
// submission Action, it adds no workflow file for detectAutoSubmission to
// find, so it would otherwise never be reported. Deliberately best effort:
// any error (dependency graph not accessible, endpoint unavailable) is
// treated as "nothing found", matching detectAutoSubmission's behavior.
func (c *DependabotCollector) detectAutoSubmissionFromSBOM(ctx context.Context, org, name string) (bool, string) {
	var response sbomResponse
	path := fmt.Sprintf("repos/%s/%s/dependency-graph/sbom", url.PathEscape(org), url.PathEscape(name))
	if err := c.client.GetJSON(ctx, path, &response); err != nil {
		return false, ""
	}
	for _, creator := range response.SBOM.CreationInfo.Creators {
		tool := strings.TrimSpace(strings.TrimPrefix(creator, "Tool:"))
		if tool == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(tool), "protobom") {
			continue
		}
		if sbomBaselineCreators[strings.ToLower(tool)] {
			continue
		}
		return true, tool
	}
	return false, ""
}

// collectAlerts reads open Dependabot (vulnerability) alerts, and separately
// derives whether alerts are enabled at all from the vulnerability-alerts
// endpoint (204 enabled, 404 disabled).
func (c *DependabotCollector) collectAlerts(ctx context.Context, org, name string, repo *model.DependabotRepo) {
	enablementPath := fmt.Sprintf("repos/%s/%s/vulnerability-alerts", url.PathEscape(org), url.PathEscape(name))
	if err := c.client.GetJSON(ctx, enablementPath, nil); err != nil {
		if isNotFoundError(err) {
			repo.Status.DependabotAlerts = model.FeatureDisabled
		} else {
			repo.Errors = append(repo.Errors, fmt.Sprintf("vulnerability alerts status: %v", err))
			repo.Status.DependabotAlerts = model.FeatureUnknown
		}
	} else {
		repo.Status.DependabotAlerts = model.FeatureEnabled
	}

	if repo.Status.DependabotAlerts != model.FeatureEnabled {
		return
	}

	var alerts []dependabotAlert
	const maxPages = 3
	const perPage = 100
	pages := 0
	lastBatchSize := 0
	listPath := fmt.Sprintf("repos/%s/%s/dependabot/alerts?state=open&per_page=%d", url.PathEscape(org), url.PathEscape(name), perPage)
	err := c.client.GetPaginatedJSON(ctx, listPath, func(page []byte) error {
		pages++
		var batch []dependabotAlert
		if err := json.Unmarshal(page, &batch); err != nil {
			return err
		}
		alerts = append(alerts, batch...)
		lastBatchSize = len(batch)
		if pages >= maxPages {
			return errStopPagination
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStopPagination) {
		repo.Errors = append(repo.Errors, fmt.Sprintf("dependabot alerts: %v", err))
		return
	}
	// A full last page (exactly perPage items) means there may be more
	// alerts beyond the page budget; a short page means that was genuinely
	// the last one. Without this check, hitting the budget would always be
	// treated as a clean, complete result, silently truncating totals,
	// severity/malware counts and the oldest-alert age for any repository
	// with more open alerts than the budget covers.
	if errors.Is(err, errStopPagination) && lastBatchSize == perPage {
		repo.Errors = append(repo.Errors, fmt.Sprintf(
			"dependabot alerts: stopped after %d pages (%d alerts) with more open alerts likely remaining",
			pages, len(alerts)))
	}

	repo.Alerts.Evaluated = true
	repo.Alerts.OpenTotal = len(alerts)
	var oldest *time.Time
	for _, alert := range alerts {
		switch strings.ToLower(alert.SecurityAdvisory.Severity) {
		case "critical":
			repo.Alerts.OpenCritical++
		case "high":
			repo.Alerts.OpenHigh++
		case "medium":
			repo.Alerts.OpenMedium++
		case "low":
			repo.Alerts.OpenLow++
		}
		if strings.EqualFold(alert.SecurityAdvisory.Classification, "malware") {
			repo.Alerts.OpenMalware++
		}
		if alert.CreatedAt != nil && (oldest == nil || alert.CreatedAt.Before(*oldest)) {
			oldest = alert.CreatedAt
		}
	}
	if oldest != nil {
		repo.Alerts.OldestOpen = timestampPtr(oldest)
		days := int(time.Since(*oldest).Hours() / 24)
		repo.Alerts.OldestOpenDays = &days
	}
}

// errStopPagination is a sentinel used to bound pagination without treating
// "enough pages read" as a real failure.
var errStopPagination = errors.New("stop pagination: page budget reached")

// dependabotAuthors identifies pull requests opened by Dependabot.
func isDependabotPullRequest(pr pullRequest) bool {
	login := strings.ToLower(pr.User.Login)
	return strings.HasPrefix(login, "dependabot")
}

// isSecurityUpdatePullRequestFallback is used only when
// collectSecurityUpdatePullRequestNumbers could not be evaluated at all (for
// example the GraphQL query failed outright). It is a best-effort heuristic
// and is known to miss real security update pull requests, since Dependabot
// does not always reference the advisory it fixes in the pull request body.
func isSecurityUpdatePullRequestFallback(pr pullRequest) bool {
	return strings.Contains(strings.ToUpper(pr.Body), "GHSA-")
}

// securityUpdateEvidence is the vulnerability alert evidence used to
// classify open Dependabot pull requests as security updates.
type securityUpdateEvidence struct {
	// pullRequestNumbers are pull requests directly and authoritatively
	// linked to a vulnerability alert via dependabotUpdate.pullRequest,
	// still open. This is definitive: such a pull request was opened to
	// remediate that alert.
	pullRequestNumbers map[int]bool
	// vulnerablePackages are the lowercased package names of alerts that did
	// not resolve to a currently open linked pull request above (no link at
	// all, or a link to a pull request that has since been closed and
	// superseded), and whose own state is not FIXED or DISMISSED (so the
	// underlying problem is still considered active). An open pull request
	// whose title names one of these packages is treated as a security
	// update: Dependabot does not normally open an unrelated pull request
	// for a package that already has an active vulnerability alert, and
	// GitHub's dependabotUpdate linkage is known to go stale (pointing at an
	// old, closed pull request) or to simply be absent for older alerts.
	vulnerablePackages map[string]bool
}

// collectSecurityUpdatePullRequestNumbers gathers evidence from
// RepositoryVulnerabilityAlert to classify open Dependabot pull requests as
// security updates, using the dependabotUpdate.pullRequest field as the
// primary, authoritative signal and the vulnerable package name as a
// secondary fallback (see securityUpdateEvidence).
//
// The query is filtered to states:[OPEN,AUTO_DISMISSED], not just OPEN.
// GitHub can auto-dismiss an alert (for example when a corrected vulnerable
// version range makes it no longer apply) while the pull request Dependabot
// already opened for it is still open and unmerged; filtering to only open
// alerts would silently drop that pull request from the security count even
// though it is still an open, unresolved security update. FIXED and
// DISMISSED alerts are excluded from the query itself (rather than merely
// ignored after fetching) because a resolved or manually-dismissed alert is
// vanishingly unlikely to still have a currently open linked pull request,
// and some repositories (long-lived demo/practice repositories in
// particular) can accumulate hundreds of historical FIXED alerts that would
// otherwise multiply this query's page count for no benefit.
//
// Pagination is additionally capped at maxAlertPages, mirroring
// collectAlerts's REST page budget: without a cap, a single repository with
// an unusually large number of open/auto-dismissed alerts could force many
// GraphQL round-trips, and with several such repositories scanned
// concurrently this measurably slows or stalls an organization-wide scan.
// A repository past this cap only loses package-name fallback coverage for
// its oldest alerts (the pullRequestNumbers linkage above is unaffected by
// ordering); it does not become an error.
//
// A nil result (as opposed to a non-nil one with empty maps) means the query
// could not be evaluated and callers should fall back to
// isSecurityUpdatePullRequestFallback.
func (c *DependabotCollector) collectSecurityUpdatePullRequestNumbers(ctx context.Context, org, name string, repo *model.DependabotRepo) *securityUpdateEvidence {
	const maxAlertPages = 5
	const query = `query($owner:String!,$name:String!,$cursor:String){
  repository(owner:$owner,name:$name){
    vulnerabilityAlerts(first:100,after:$cursor,states:[OPEN,AUTO_DISMISSED]){
      pageInfo{hasNextPage endCursor}
      nodes{
        state
        securityVulnerability{
          package{name}
        }
        dependabotUpdate{
          pullRequest{number state}
        }
      }
    }
  }
}`

	evidence := &securityUpdateEvidence{pullRequestNumbers: map[int]bool{}, vulnerablePackages: map[string]bool{}}
	cursor := ""
	for page := 0; page < maxAlertPages; page++ {
		var response vulnerabilityAlertsPullRequestsResponse
		variables := map[string]any{"owner": org, "name": name, "cursor": (*string)(nil)}
		if cursor != "" {
			variables["cursor"] = cursor
		}
		if err := c.client.GraphQL(ctx, query, variables, &response); err != nil {
			repo.Errors = append(repo.Errors, fmt.Sprintf("vulnerability alert pull request linkage: %v", err))
			return nil
		}
		if response.Repository == nil {
			repo.Errors = append(repo.Errors, "vulnerability alert pull request linkage: repository not found")
			return nil
		}
		for _, node := range response.Repository.VulnerabilityAlerts.Nodes {
			linkedToOpenPR := false
			if node.DependabotUpdate != nil && node.DependabotUpdate.PullRequest != nil &&
				strings.EqualFold(node.DependabotUpdate.PullRequest.State, "OPEN") {
				evidence.pullRequestNumbers[node.DependabotUpdate.PullRequest.Number] = true
				linkedToOpenPR = true
			}
			if linkedToOpenPR {
				continue
			}
			if node.SecurityVulnerability != nil && node.SecurityVulnerability.Package != nil && node.SecurityVulnerability.Package.Name != "" {
				evidence.vulnerablePackages[strings.ToLower(node.SecurityVulnerability.Package.Name)] = true
			}
		}
		if !response.Repository.VulnerabilityAlerts.PageInfo.HasNextPage {
			return evidence
		}
		if page == maxAlertPages-1 {
			// The page budget was exhausted while the server still reports
			// more alerts remaining. The linkage map built so far is
			// genuinely partial: a security pull request linked only from
			// an omitted alert would otherwise be silently counted as a
			// version update (and could even look like a false backlog).
			// Report this as a collection error so it cannot be mistaken
			// for complete, confident evidence.
			repo.Errors = append(repo.Errors, fmt.Sprintf(
				"vulnerability alert pull request linkage: stopped after %d pages with more alerts remaining; "+
					"pull request security/version classification may be incomplete", maxAlertPages))
			break
		}
		cursor = response.Repository.VulnerabilityAlerts.PageInfo.EndCursor
	}
	return evidence
}

// pullRequestReferencesVulnerablePackage reports whether a pull request's
// title or body names one of the given packages as a whole token, not
// merely as a substring of a longer, unrelated package name (for example
// "es" must not match inside "eslint"). The body is checked in addition to
// the title because Dependabot's grouped-update pull requests (for example
// "Bump the pip group across 1 directory with 6 updates") never name
// individual packages in the title at all; only the body's dependency table
// does.
func pullRequestReferencesVulnerablePackage(pr pullRequest, packages map[string]bool) bool {
	if len(packages) == 0 {
		return false
	}
	haystack := strings.ToLower(pr.Title + "\n" + pr.Body)
	for name := range packages {
		if containsPackageToken(haystack, name) {
			return true
		}
	}
	return false
}

func containsPackageToken(haystack, name string) bool {
	if name == "" {
		return false
	}
	for start := 0; ; {
		index := strings.Index(haystack[start:], name)
		if index < 0 {
			return false
		}
		matchStart := start + index
		matchEnd := matchStart + len(name)
		beforeIsBoundary := matchStart == 0 || !isPackageTokenByte(haystack[matchStart-1])
		afterIsBoundary := matchEnd == len(haystack) || !isPackageTokenByte(haystack[matchEnd])
		if beforeIsBoundary && afterIsBoundary {
			return true
		}
		start = matchStart + 1
	}
}

// isPackageTokenByte reports whether b can be part of a package name token,
// so that a boundary check does not split "node-forge" or "@scope/name" at
// their internal punctuation.
func isPackageTokenByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '-' || b == '_' || b == '.' || b == '/' || b == '@':
		return true
	default:
		return false
	}
}

// collectPullRequests reads open Dependabot pull requests, their combined
// status and check-run conclusions, and whether Dependabot activity is
// paused for inactivity. authoritativePaused is the result of
// collectAutomatedSecurityFixes: when non-nil, it is trusted over the
// best-effort "dependabot-paused" pull request label, since the label is
// only a proxy that can lag the real state and cannot be observed at all
// when there are zero open pull requests. When nil (the authoritative check
// was unavailable), the label remains the fallback signal.
func (c *DependabotCollector) collectPullRequests(ctx context.Context, org, name string, repo *model.DependabotRepo, authoritativePaused *bool) {
	// Recorded immediately, before any early return below, so a repository
	// confirmed paused by the authoritative check is never reported as not
	// paused merely because it happens to have zero open pull requests or
	// because the pull request list itself could not be fetched.
	if authoritativePaused != nil {
		repo.PullRequests.PausedForInactivity = *authoritativePaused
	}

	var pulls []pullRequest
	listPath := fmt.Sprintf("repos/%s/%s/pulls?state=open&per_page=100", url.PathEscape(org), url.PathEscape(name))
	if err := c.client.GetPaginatedJSON(ctx, listPath, func(page []byte) error {
		var batch []pullRequest
		if err := json.Unmarshal(page, &batch); err != nil {
			return err
		}
		pulls = append(pulls, batch...)
		return nil
	}); err != nil {
		repo.Errors = append(repo.Errors, fmt.Sprintf("pull requests: %v", err))
		repo.Status.PullRequestHealth = model.PRHealthUnknown
		return
	}

	var dependabotPulls []pullRequest
	for _, pr := range pulls {
		if isDependabotPullRequest(pr) {
			dependabotPulls = append(dependabotPulls, pr)
		}
	}

	repo.PullRequests.Evaluated = true
	repo.PullRequests.Open = len(dependabotPulls)

	if len(dependabotPulls) == 0 {
		repo.Status.PullRequestHealth = model.PRHealthNone
		return
	}

	evidence := c.collectSecurityUpdatePullRequestNumbers(ctx, org, name, repo)

	paused := repo.PullRequests.PausedForInactivity
	var oldest *time.Time
	const maxStatusChecks = 25
	checked := 0
	// uncheckedPulls counts pull requests whose failing-check status could
	// not be established, either because the per-scan check budget was
	// exhausted or because a status/check-run request failed. These must
	// not be silently folded into a confident "healthy" verdict: see the
	// switch below.
	uncheckedPulls := 0
	for _, pr := range dependabotPulls {
		isSecurity := false
		if evidence != nil {
			isSecurity = evidence.pullRequestNumbers[pr.Number] || pullRequestReferencesVulnerablePackage(pr, evidence.vulnerablePackages)
		} else {
			isSecurity = isSecurityUpdatePullRequestFallback(pr)
		}
		if isSecurity {
			repo.PullRequests.OpenSecurityUpdates++
		} else {
			repo.PullRequests.OpenVersionUpdates++
		}
		if pr.CreatedAt != nil && (oldest == nil || pr.CreatedAt.Before(*oldest)) {
			oldest = pr.CreatedAt
		}
		if authoritativePaused == nil {
			for _, label := range pr.Labels {
				if strings.EqualFold(label.Name, "dependabot-paused") {
					paused = true
				}
			}
		}

		if pr.Head.SHA == "" {
			uncheckedPulls++
			continue
		}
		if checked >= maxStatusChecks {
			uncheckedPulls++
			continue
		}
		checked++

		failing, err := c.pullRequestHasFailingChecks(ctx, org, name, pr.Head.SHA)
		if err != nil {
			uncheckedPulls++
			continue
		}
		if failing {
			repo.PullRequests.OpenFailingChecks++
		}
	}

	if oldest != nil {
		repo.PullRequests.OldestOpen = timestampPtr(oldest)
		days := int(time.Since(*oldest).Hours() / 24)
		repo.PullRequests.OldestOpenDays = &days
	}
	if authoritativePaused == nil {
		repo.PullRequests.PausedForInactivity = paused
	}

	if uncheckedPulls > 0 {
		repo.Errors = append(repo.Errors, fmt.Sprintf(
			"pull request checks: %d of %d open Dependabot pull requests could not be checked for failing checks",
			uncheckedPulls, len(dependabotPulls)))
	}

	openPRLimit := versionUpdatesLimit(repo)

	switch {
	case repo.PullRequests.OpenFailingChecks > 0:
		repo.Status.PullRequestHealth = model.PRHealthFailingChecks
	case uncheckedPulls > 0:
		// Nothing confirmed failing among the pull requests that were
		// checked, but at least one pull request's status could not be
		// established at all; reporting healthy here would claim
		// certainty the collector does not have.
		repo.Status.PullRequestHealth = model.PRHealthUnknown
	case paused:
		repo.Status.VersionUpdates = model.VersionUpdatesPausedInactivity
		repo.Status.PullRequestHealth = model.PRHealthHealthy
	case openPRLimit > 0 && repo.PullRequests.OpenVersionUpdates >= openPRLimit:
		repo.Status.PullRequestHealth = model.PRHealthBacklogged
	default:
		repo.Status.PullRequestHealth = model.PRHealthHealthy
	}
}

// failingCheckRunConclusions are the check-run conclusions this collector
// treats as a definite failure. "skipped", "neutral" and "stale" are
// deliberately excluded: they are ordinary, often intentional outcomes (for
// example a path-filtered workflow that never ran for this PR), not
// evidence of a problem.
var failingCheckRunConclusions = map[string]bool{
	"failure":         true,
	"timed_out":       true,
	"cancelled":       true,
	"action_required": true,
}

// pullRequestHasFailingChecks reports whether a commit has a failing result
// from either of GitHub's two independent check systems. The legacy
// Combined Status endpoint only reflects statuses posted through the
// Statuses API; it does not reflect Checks API results, which is what
// GitHub Actions (and most modern third-party CI) actually posts. Relying
// on the combined status alone therefore misses virtually all
// Actions-based CI failures. Both are queried and either reporting a
// failure is treated as the pull request having a failing check.
func (c *DependabotCollector) pullRequestHasFailingChecks(ctx context.Context, org, name, sha string) (bool, error) {
	var status combinedStatus
	statusPath := fmt.Sprintf("repos/%s/%s/commits/%s/status", url.PathEscape(org), url.PathEscape(name), sha)
	if err := c.client.GetJSON(ctx, statusPath, &status); err != nil {
		return false, err
	}
	if strings.EqualFold(status.State, "failure") || strings.EqualFold(status.State, "error") {
		return true, nil
	}

	var checkRuns checkRunsResponse
	checkRunsPath := fmt.Sprintf("repos/%s/%s/commits/%s/check-runs?per_page=100", url.PathEscape(org), url.PathEscape(name), sha)
	if err := c.client.GetJSON(ctx, checkRunsPath, &checkRuns); err != nil {
		return false, err
	}
	for _, run := range checkRuns.CheckRuns {
		if !strings.EqualFold(run.Status, "completed") {
			continue
		}
		if failingCheckRunConclusions[strings.ToLower(run.Conclusion)] {
			return true, nil
		}
	}
	return false, nil
}

// versionUpdatesLimit returns the effective open-pull-requests-limit for
// version updates. dependabot.yml is not re-parsed here; the collector keeps
// the raw update blocks only long enough to compute this, via the ecosystem
// list already recorded, defaulting to GitHub's documented default of 5 per
// update block when unset.
//
// This is a repository-wide, per-ecosystem approximation, not a per-block
// one: multiple update blocks for the same ecosystem (for example two
// separate npm directories) have their limits summed, but open version
// update pull requests are not individually attributed back to the specific
// block that opened them (Dependabot's pull request payloads do not
// directly expose which configured block a pull request came from). A
// saturated block can therefore still be masked by headroom in a different,
// unsaturated block for the same ecosystem; see model.VersionUpdatesDetail
// for the per-block limits this is computed from.
func versionUpdatesLimit(repo *model.DependabotRepo) int {
	if len(repo.VersionUpdates.EcosystemLimits) == 0 {
		return 0
	}
	total := 0
	for _, limit := range repo.VersionUpdates.EcosystemLimits {
		total += limit
	}
	return total
}

// collectDependencyReview checks the repository default branch's effective
// ruleset rules for a required status check matching the configured
// dependency-review pattern. There is no native "dependency review" rule
// type; enforcement is always a required_status_checks rule referencing a
// job/context name that varies by configuration.
func (c *DependabotCollector) collectDependencyReview(ctx context.Context, org, name string, repo *model.DependabotRepo) {
	if repo.DefaultBranch == "" {
		repo.Status.DependencyReview = model.DependencyReviewUnknown
		return
	}

	if repo.TemporarySecurityAdvisoryFork {
		// GitHub's temporary private security-advisory forks always return
		// 404 from the rules and rulesets endpoints, regardless of any
		// ruleset actually configured on the real repository. That 404 is a
		// structural property of the fork, not missing or incomplete
		// evidence, so this check is skipped entirely (and the guaranteed-
		// to-fail request is never made) rather than being recorded as a
		// collection error.
		repo.Status.DependencyReview = model.DependencyReviewNotEvaluated
		return
	}

	var rules []branchRule
	rulesPath := fmt.Sprintf("repos/%s/%s/rules/branches/%s", url.PathEscape(org), url.PathEscape(name), url.PathEscape(repo.DefaultBranch))
	if err := c.client.GetJSON(ctx, rulesPath, &rules); err != nil {
		repo.Errors = append(repo.Errors, fmt.Sprintf("branch rules: %v", err))
		repo.Status.DependencyReview = model.DependencyReviewUnknown
		return
	}

	repo.DependencyReview.Evaluated = true
	repo.DependencyReview.Branch = repo.DefaultBranch
	repo.DependencyReview.Pattern = c.options.DependencyReviewCheckPattern

	pattern := strings.ToLower(repo.DependencyReview.Pattern)
	for _, rule := range rules {
		if rule.Type != "required_status_checks" {
			continue
		}
		for _, check := range rule.Parameters.RequiredStatusChecks {
			if strings.Contains(strings.ToLower(check.Context), pattern) {
				repo.DependencyReview.MatchedCheckContext = check.Context
				repo.Status.DependencyReview = model.DependencyReviewEnforced
				return
			}
		}
	}

	// Rulesets are not the only way a required status check gets enforced:
	// the older, separate classic branch-protection system
	// (required_status_checks) is invisible to the rules/branches endpoint
	// above. A repository relying solely on classic protection for its
	// dependency-review check would otherwise always be misreported as
	// not-enforced.
	var classic classicRequiredStatusChecks
	classicPath := fmt.Sprintf("repos/%s/%s/branches/%s/protection/required_status_checks", url.PathEscape(org), url.PathEscape(name), url.PathEscape(repo.DefaultBranch))
	if err := c.client.GetJSON(ctx, classicPath, &classic); err != nil {
		if !isNotFoundError(err) {
			// A 404 here just means no classic protection is configured,
			// which is a normal, non-error outcome (rulesets may still
			// cover the branch). Anything else is a genuine collection
			// failure that leaves enforcement unconfirmed.
			repo.Errors = append(repo.Errors, fmt.Sprintf("classic branch protection: %v", err))
			repo.Status.DependencyReview = model.DependencyReviewUnknown
			return
		}
	} else {
		for _, context := range classic.Contexts {
			if strings.Contains(strings.ToLower(context), pattern) {
				repo.DependencyReview.MatchedCheckContext = context
				repo.Status.DependencyReview = model.DependencyReviewEnforced
				return
			}
		}
		for _, check := range classic.Checks {
			if strings.Contains(strings.ToLower(check.Context), pattern) {
				repo.DependencyReview.MatchedCheckContext = check.Context
				repo.Status.DependencyReview = model.DependencyReviewEnforced
				return
			}
		}
	}

	repo.Status.DependencyReview = model.DependencyReviewNotEnforced
}
