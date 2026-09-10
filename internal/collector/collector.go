// Package collector gathers code scanning status across organizations and
// enterprises and produces the versioned report defined in internal/model.
package collector

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/advanced-security/gh-ghas-audit/internal/ghapi"
	"github.com/advanced-security/gh-ghas-audit/internal/model"
)

var (
	// errConfigurationsUnavailable signals that code security configuration
	// APIs are not present, which is expected on older GitHub Enterprise
	// Server releases.
	errConfigurationsUnavailable = errors.New("code security configuration API unavailable")
	// errPropertiesUnavailable signals that custom properties are not
	// readable for the organization.
	errPropertiesUnavailable = errors.New("custom properties API unavailable")
)

// DeepDiagnosticsMode selects how aggressively Actions logs are inspected.
type DeepDiagnosticsMode string

const (
	// DeepDiagnosticsOff performs no log retrieval. This is the default.
	DeepDiagnosticsOff DeepDiagnosticsMode = ""
	// DeepDiagnosticsProblematic inspects only repositories that already look
	// unhealthy, which keeps the extra cost proportional to the problem.
	DeepDiagnosticsProblematic DeepDiagnosticsMode = "problematic"
	// DeepDiagnosticsAll inspects every configured repository, including
	// healthy ones. This is the only mode that can surface warnings hidden
	// behind a green workflow run, and it is substantially more expensive.
	DeepDiagnosticsAll DeepDiagnosticsMode = "all"
)

// LogFetcher retrieves and interprets Actions logs. It is satisfied by
// internal/diagnostics and injected so the collector has no hard dependency on
// best-effort log parsing.
type LogFetcher interface {
	Inspect(ctx context.Context, org, repo string, runID int64) ([]model.Diagnostic, error)
}

// Client is the subset of the GitHub API surface the collector depends on.
// Declaring it as an interface keeps collection logic testable without
// network access, which matters because the classification rules are the part
// most likely to regress.
type Client interface {
	Host() string
	Stats() *ghapi.Stats
	WarnOnce(key string) bool
	GetJSON(ctx context.Context, path string, out any) error
	GetPaginatedJSON(ctx context.Context, path string, collect func(page []byte) error) error
	GraphQL(ctx context.Context, query string, variables map[string]any, out any) error
}

// Options configures a collection run.
type Options struct {
	Enterprise    string
	Organizations []string
	// Repository restricts the scan to a single "owner/name" repository.
	Repository string

	SkipArchived          bool
	SkipForks             bool
	SecurityConfiguration string

	// StaleAfter is how old successful scan evidence may be before an active
	// repository is reported as stale.
	StaleAfter time.Duration
	// StaleAfterInactive is the equivalent threshold for repositories GitHub
	// scans monthly because they have had no pushes for a long time. Zero
	// disables staleness checking for those repositories, which suits an
	// organization that has not enabled monthly scanning of inactive
	// repositories.
	StaleAfterInactive time.Duration
	// InactiveAfter is how long without a push makes a repository inactive.
	// Zero treats every repository as active.
	InactiveAfter time.Duration

	Concurrency int

	// Properties limits which custom properties are included in output.
	// Empty includes all of them.
	Properties []string
	// GroupByProperty aggregates summary counts by a custom property value,
	// which is how repositories are mapped onto applications.
	GroupByProperty string
	// PropertyFilters restricts the scan to repositories whose property
	// values match, keyed by property name.
	PropertyFilters map[string][]string

	VisibilityFilter []string
	NameFilter       []string
	ExcludeFilter    []string

	DeepDiagnostics DeepDiagnosticsMode
	LogFetcher      LogFetcher

	// Progress receives human-readable progress messages.
	Progress func(message string)
	// OnRepository is invoked as each repository completes, enabling
	// streaming output for very large estates. Calls are serialized, so the
	// callback does not need to be safe for concurrent use.
	OnRepository func(repo model.Repo)

	// Now allows tests to control the clock used for staleness.
	Now func() time.Time
}

// Collector executes a status collection.
type Collector struct {
	client  Client
	options Options

	mu       sync.Mutex
	warnings []string
}

// New creates a Collector.
func New(client Client, options Options) *Collector {
	if options.Concurrency <= 0 {
		options.Concurrency = 8
	}
	if options.StaleAfter <= 0 {
		options.StaleAfter = 8 * 24 * time.Hour
	}
	return &Collector{client: client, options: options}
}
func (c *Collector) now() time.Time {
	if c.options.Now != nil {
		return c.options.Now()
	}
	return time.Now()
}

func (c *Collector) progress(format string, args ...any) {
	if c.options.Progress == nil {
		return
	}
	c.options.Progress(fmt.Sprintf(format, args...))
}

func (c *Collector) warn(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	c.mu.Lock()
	c.warnings = append(c.warnings, message)
	c.mu.Unlock()
}

// Collect runs the scan and returns a fully populated report.
func (c *Collector) Collect(ctx context.Context, toolVersion string) (*model.Report, error) {
	started := c.now()

	organizations, err := c.resolveOrganizations(ctx)
	if err != nil {
		return nil, err
	}
	if len(organizations) == 0 {
		return nil, errors.New("no organizations to scan; pass --organization, --enterprise or --repository")
	}

	var repositories []model.Repo
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

	model.SortRepos(repositories)

	report := &model.Report{
		SchemaVersion: model.SchemaVersion,
		GeneratedAt:   c.now(),
		Tool:          model.ToolInfo{Name: "gh-ghas-audit", Version: toolVersion},
		Scope: model.Scope{
			Host:          c.client.Host(),
			Enterprise:    c.options.Enterprise,
			Organizations: organizations,
			Repository:    c.options.Repository,
		},
		Settings: model.Settings{
			StaleAfter:            formatDuration(c.options.StaleAfter),
			StaleAfterSeconds:     c.options.StaleAfter.Seconds(),
			StaleAfterInactive:    describeInactiveThreshold(c.options.StaleAfterInactive),
			InactiveAfter:         describeInactiveWindow(c.options.InactiveAfter),
			SkipArchived:          c.options.SkipArchived,
			SkipForks:             c.options.SkipForks,
			SecurityConfiguration: c.options.SecurityConfiguration,
			Properties:            c.options.Properties,
			GroupByProperty:       c.options.GroupByProperty,
			Concurrency:           c.options.Concurrency,
			DeepDiagnostics:       string(c.options.DeepDiagnostics),
		},
		Repositories: repositories,
		Summary:      model.BuildSummary(repositories, c.options.GroupByProperty),
	}

	report.Organizations = model.BuildOrgReports(repositories)
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
		Incomplete:       len(report.Warnings) > 0 || anyRepoErrors(repositories),
	}

	return report, nil
}

func anyRepoErrors(repositories []model.Repo) bool {
	for _, repo := range repositories {
		if len(repo.Errors) > 0 {
			return true
		}
	}
	return false
}

// resolveOrganizations determines the organizations in scope, expanding an
// enterprise when one is supplied.
func (c *Collector) resolveOrganizations(ctx context.Context) ([]string, error) {
	unique := map[string]bool{}
	var ordered []string
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" || unique[name] {
			return
		}
		unique[name] = true
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

// collectOrganization scans a single organization.
func (c *Collector) collectOrganization(ctx context.Context, org string) ([]model.Repo, error) {
	configurations, err := c.loadConfigurations(ctx, org, c.options.SecurityConfiguration)
	switch {
	case errors.Is(err, errConfigurationsUnavailable):
		// A filter that cannot be evaluated must fail loudly. Continuing would
		// silently exclude every repository and produce an empty report that
		// looks like a clean bill of health.
		if c.options.SecurityConfiguration != "" {
			return nil, fmt.Errorf(
				"--security-configuration %q cannot be applied to %s: code security configuration data is unavailable, "+
					"which usually means the token lacks organization administration access",
				c.options.SecurityConfiguration, org)
		}
		if c.client.WarnOnce("configurations:" + org) {
			c.warn("code security configuration data is unavailable for %s; "+
				"attachment status will be omitted and failed rollouts cannot be detected", org)
		}
	case err != nil:
		return nil, err
	}

	properties := map[string]map[string]string{}
	if c.needsProperties() {
		loaded, err := c.loadProperties(ctx, org)
		switch {
		case err != nil:
			if len(c.options.PropertyFilters) > 0 {
				return nil, fmt.Errorf(
					"--property-filter cannot be applied to %s: custom properties could not be read (%w)", org, err)
			}
			if errors.Is(err, errPropertiesUnavailable) {
				if c.client.WarnOnce("properties:" + org) {
					c.warn("custom properties are unavailable for %s; grouping will show every repository as (not set)", org)
				}
			} else {
				c.warn("custom properties could not be read for %s: %v", org, err)
			}
		default:
			properties = loaded
		}
	}

	sources, err := c.listOrganizationRepositories(ctx, org)
	if err != nil {
		return nil, err
	}

	eligible := make([]apiRepository, 0, len(sources))
	for _, source := range sources {
		if c.skipRepository(source, properties[source.Name], configurations) {
			continue
		}
		eligible = append(eligible, source)
	}

	c.progress("Scanning %s: %d of %d repositories in scope", org, len(eligible), len(sources))

	return c.scanRepositories(ctx, org, eligible, properties, configurations)
}

// needsProperties reports whether custom property values have to be fetched.
func (c *Collector) needsProperties() bool {
	return c.options.Repository == "" ||
		c.options.GroupByProperty != "" ||
		len(c.options.PropertyFilters) > 0 ||
		len(c.options.Properties) > 0
}

func (c *Collector) listOrganizationRepositories(ctx context.Context, org string) ([]apiRepository, error) {
	if c.options.Repository != "" {
		_, name, ok := splitRepository(c.options.Repository)
		if !ok {
			return nil, fmt.Errorf("invalid repository %q; expected OWNER/REPO", c.options.Repository)
		}
		repo, err := c.getRepository(ctx, org, name)
		if err != nil {
			return nil, err
		}
		return []apiRepository{repo}, nil
	}
	return c.listRepositories(ctx, org)
}

// scanRepositories fans out per-repository collection across a bounded worker
// pool, preserving deterministic ordering in the returned slice.
func (c *Collector) scanRepositories(
	ctx context.Context,
	org string,
	sources []apiRepository,
	properties map[string]map[string]string,
	configurations *configurationIndex,
) ([]model.Repo, error) {
	results := make([]model.Repo, len(sources))
	included := make([]bool, len(sources))

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

				extra := repoContext{Properties: c.filterProperties(properties[source.Name])}
				if configurations != nil {
					if configuration, ok := configurations.byRepo[source.Name]; ok {
						extra.ConfigurationName = configuration.ConfigurationName
						extra.AttachmentStatus = configuration.Status
					}
				}

				repo := c.collectRepository(ctx, org, source, extra)
				c.applyDeepDiagnostics(ctx, &repo)

				// Each worker owns a distinct index, so the shared slices are
				// written without contention.
				results[index] = repo
				included[index] = true

				progressMu.Lock()
				if c.options.OnRepository != nil {
					c.options.OnRepository(repo)
				}
				completed++
				if completed%25 == 0 || completed == len(sources) {
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

	final := make([]model.Repo, 0, len(results))
	for index, keep := range included {
		if keep {
			final = append(final, results[index])
		}
	}
	return final, nil
}

// applyDeepDiagnostics optionally augments a repository with best-effort
// findings parsed from Actions logs.
func (c *Collector) applyDeepDiagnostics(ctx context.Context, repo *model.Repo) {
	if c.options.LogFetcher == nil || c.options.DeepDiagnostics == DeepDiagnosticsOff {
		return
	}
	if c.options.DeepDiagnostics == DeepDiagnosticsProblematic && !model.NeedsAttention(repo.Status.Overall) {
		return
	}

	run := repo.Execution.LatestCompletedRun
	if run == nil {
		return
	}

	diagnostics, err := c.options.LogFetcher.Inspect(ctx, repo.Organization, repo.Name, run.ID)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		// The inspection did not happen, so the repository must be
		// reclassified as incomplete rather than left with its earlier
		// verdict.
		repo.Errors = append(repo.Errors, fmt.Sprintf("deep diagnostics: %v", err))
		finalizeStatus(repo, hasWarningDiagnostic(repo.Diagnostics))
		return
	}
	if len(diagnostics) == 0 {
		return
	}

	repo.Diagnostics = append(repo.Diagnostics, diagnostics...)
	// A log-derived warning can promote an otherwise healthy repository to
	// degraded, which is the "green run, low quality scan" case.
	finalizeStatus(repo, hasWarningDiagnostic(repo.Diagnostics))
}

// skipRepository applies filters that can be evaluated before any per-
// repository API calls, so excluded repositories cost nothing.
func (c *Collector) skipRepository(source apiRepository, properties map[string]string, configurations *configurationIndex) bool {
	if c.options.SkipArchived && source.IsArchived {
		return true
	}
	if c.options.SkipForks && source.IsFork {
		return true
	}
	if len(c.options.VisibilityFilter) > 0 && !matchesAny(strings.ToLower(source.Visibility), c.options.VisibilityFilter) {
		return true
	}
	if len(c.options.NameFilter) > 0 && !matchesAny(strings.ToLower(source.Name), c.options.NameFilter) {
		return true
	}
	if len(c.options.ExcludeFilter) > 0 && matchesAny(strings.ToLower(source.Name), c.options.ExcludeFilter) {
		return true
	}
	if configurations != nil && configurations.filterActive && !configurations.filterMatched[source.Name] {
		return true
	}
	for name, wanted := range c.options.PropertyFilters {
		value, _ := model.PropertyValue(properties, name)
		if !propertyMatches(value, wanted) {
			return true
		}
	}
	return false
}

// propertyMatches reports whether a custom property value satisfies a filter.
//
// Multi-select properties arrive as a joined list, so each element is matched
// individually. Filtering on Project=WUPH must select a repository whose
// Project is "WUPH, Internal".
func propertyMatches(value string, patterns []string) bool {
	if matchesAny(value, patterns) {
		return true
	}
	if !strings.Contains(value, ",") {
		return false
	}
	for _, element := range strings.Split(value, ",") {
		if matchesAny(strings.TrimSpace(element), patterns) {
			return true
		}
	}
	return false
}

// matchesPostFilters applies filters that require a classified repository.
func (c *Collector) matchesPostFilters(repo model.Repo) bool {
	return true
}

// filterProperties limits the recorded properties to those requested.
func (c *Collector) filterProperties(properties map[string]string) map[string]string {
	if len(properties) == 0 {
		return nil
	}

	// Copy before appending. The options slice comes straight from the flag
	// parser and can have spare capacity, so appending in place would let
	// concurrent workers write into the same backing array.
	wanted := append([]string(nil), c.options.Properties...)
	if c.options.GroupByProperty != "" {
		wanted = append(wanted, c.options.GroupByProperty)
	}
	for name := range c.options.PropertyFilters {
		wanted = append(wanted, name)
	}

	if len(wanted) == 0 {
		copied := make(map[string]string, len(properties))
		for key, value := range properties {
			copied[key] = value
		}
		return copied
	}

	// Match requested names case-insensitively, but store the organization's
	// own spelling so output shows the real property name.
	filtered := map[string]string{}
	for _, name := range wanted {
		for key, value := range properties {
			if strings.EqualFold(key, name) {
				filtered[key] = value
			}
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

// matchesAny performs case-insensitive glob matching, supporting the "team-*"
// naming conventions commonly used to select repositories. Both the value and
// the patterns are normalized here so callers cannot get the casing wrong.
func matchesAny(value string, patterns []string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, pattern := range patterns {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		if pattern == value {
			return true
		}
		if matched, err := path.Match(pattern, value); err == nil && matched {
			return true
		}
	}
	return false
}

func splitRepository(value string) (string, string, bool) {
	parts := strings.SplitN(strings.TrimSpace(value), "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// formatDuration renders a duration using day granularity where possible,
// matching the way the flag is supplied.
func formatDuration(duration time.Duration) string {
	if duration%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", int(duration.Hours()/24))
	}
	return duration.String()
}

// describeInactiveThreshold renders the inactive staleness setting, making an
// explicitly disabled check visible in the report rather than implied.
func describeInactiveThreshold(duration time.Duration) string {
	if duration <= 0 {
		return "off"
	}
	return formatDuration(duration)
}

func describeInactiveWindow(duration time.Duration) string {
	if duration <= 0 {
		return "off"
	}
	return formatDuration(duration)
}
