package model

import (
	"sort"
	"strings"
	"time"
)

// Timestamp is an alias for time.Time so report fields marshal as RFC 3339.
type Timestamp = time.Time

// Report is the top-level, versioned document emitted by a status collection.
// It is the canonical interface for every downstream consumer; the table, CSV
// and NDJSON writers are all projections of this structure.
type Report struct {
	SchemaVersion string      `json:"schema_version"`
	GeneratedAt   Timestamp   `json:"generated_at"`
	Tool          ToolInfo    `json:"tool"`
	Scope         Scope       `json:"scope"`
	Settings      Settings    `json:"settings"`
	Summary       Summary     `json:"summary"`
	Organizations []OrgReport `json:"organizations"`
	Repositories  []Repo      `json:"repositories"`
	// Warnings records non-fatal collection problems, such as an organization
	// that could not be read. Their presence means the report is incomplete.
	Warnings []string `json:"warnings,omitempty"`
	Stats    Stats    `json:"stats"`
}

// ToolInfo identifies the producer of a report.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Scope records what was requested, so a stored report is self-describing.
type Scope struct {
	Host          string   `json:"host"`
	Enterprise    string   `json:"enterprise,omitempty"`
	Organizations []string `json:"organizations,omitempty"`
	Repository    string   `json:"repository,omitempty"`
}

// Settings records the thresholds and options that produced the results, so
// that a stale classification can always be explained after the fact.
type Settings struct {
	StaleAfter            string   `json:"stale_after"`
	StaleAfterSeconds     float64  `json:"stale_after_seconds"`
	SkipArchived          bool     `json:"skip_archived"`
	SkipForks             bool     `json:"skip_forks"`
	SecurityConfiguration string   `json:"security_configuration,omitempty"`
	Properties            []string `json:"properties,omitempty"`
	GroupByProperty       string   `json:"group_by_property,omitempty"`
	Concurrency           int      `json:"concurrency"`
	DeepDiagnostics       string   `json:"deep_diagnostics,omitempty"`
}

// Summary holds aggregate counts for an entire report.
type Summary struct {
	TotalRepositories int            `json:"total_repositories"`
	BySeverity        map[string]int `json:"by_severity"`
	ByConfiguration   map[string]int `json:"by_configuration"`
	ByExecution       map[string]int `json:"by_execution"`
	ByFreshness       map[string]int `json:"by_freshness"`
	ByCoverage        map[string]int `json:"by_coverage"`
	// NeedsAttention counts repositories whose severity is actionable
	// (failing, stalled, stale or degraded).
	NeedsAttention int `json:"needs_attention"`
	// Groups holds counts keyed by the value of --group-by-property.
	Groups []GroupSummary `json:"groups,omitempty"`
}

// GroupSummary aggregates repositories that share a custom property value,
// which is how customers map repositories onto applications.
type GroupSummary struct {
	Property       string         `json:"property"`
	Value          string         `json:"value"`
	Repositories   int            `json:"repositories"`
	NeedsAttention int            `json:"needs_attention"`
	BySeverity     map[string]int `json:"by_severity"`
}

// OrgReport summarizes a single organization.
type OrgReport struct {
	Login             string         `json:"login"`
	TotalRepositories int            `json:"total_repositories"`
	NeedsAttention    int            `json:"needs_attention"`
	BySeverity        map[string]int `json:"by_severity"`
	// Error is set when the organization could not be inspected at all.
	Error string `json:"error,omitempty"`
}

// Repo is the per-repository record: the unit customers triage.
type Repo struct {
	Organization  string     `json:"organization"`
	Name          string     `json:"name"`
	FullName      string     `json:"full_name"`
	URL           string     `json:"url"`
	Visibility    string     `json:"visibility"`
	Archived      bool       `json:"archived"`
	Fork          bool       `json:"fork"`
	DefaultBranch string     `json:"default_branch"`
	PushedAt      *Timestamp `json:"pushed_at,omitempty"`

	Status        Status          `json:"status"`
	Configuration ConfigDetail    `json:"configuration"`
	Execution     ExecutionDetail `json:"execution"`

	// Languages is the per-language breakdown that shows whether a green
	// workflow actually analyzed everything it should have.
	Languages []LanguageState `json:"languages,omitempty"`
	// DetectedLanguages lists supported languages found in the source.
	DetectedLanguages []Language `json:"detected_languages,omitempty"`
	// ConfiguredLanguages lists languages default setup intends to analyze.
	ConfiguredLanguages []Language `json:"configured_languages,omitempty"`
	// SucceededLanguages lists languages with successful analysis evidence.
	SucceededLanguages []Language `json:"succeeded_languages,omitempty"`
	// MissingLanguages lists supported detected languages that are not
	// configured for analysis, the "scan drift" gap.
	MissingLanguages []Language `json:"missing_languages,omitempty"`
	// UnsupportedLanguages lists languages present in the repository that
	// CodeQL cannot analyze at all, such as Scala or Objective-C. These are
	// not a misconfiguration, but customers need them to know where CodeQL
	// alone does not provide coverage.
	UnsupportedLanguages []string `json:"unsupported_languages,omitempty"`
	// FailedLanguages lists configured languages without successful evidence.
	FailedLanguages []Language `json:"failed_languages,omitempty"`

	// LastSuccessfulScan is the newest successful analysis evidence, used for
	// "when did this repository last actually scan" questions.
	LastSuccessfulScan *Timestamp `json:"last_successful_scan,omitempty"`
	// StaleDays is how old that evidence is, in whole days.
	StaleDays *int `json:"stale_days,omitempty"`

	Properties  map[string]string `json:"properties,omitempty"`
	Diagnostics []Diagnostic      `json:"diagnostics,omitempty"`
	// Errors records per-repository collection failures. A repository with
	// errors has incomplete data and must not be read as healthy.
	Errors []string `json:"errors,omitempty"`
}

// ConfigDetail captures how code scanning is set up for a repository.
type ConfigDetail struct {
	DefaultSetupState string     `json:"default_setup_state,omitempty"`
	QuerySuite        string     `json:"query_suite,omitempty"`
	Schedule          string     `json:"schedule,omitempty"`
	ThreatModel       string     `json:"threat_model,omitempty"`
	RunnerType        string     `json:"runner_type,omitempty"`
	RunnerLabel       string     `json:"runner_label,omitempty"`
	UpdatedAt         *Timestamp `json:"updated_at,omitempty"`
	// SecurityConfiguration is the attached org/enterprise configuration.
	SecurityConfiguration string `json:"security_configuration,omitempty"`
	// AttachmentStatus is the raw configuration attachment state, which
	// exposes failed rollouts that default setup alone does not reveal.
	AttachmentStatus string `json:"attachment_status,omitempty"`
}

// ExecutionDetail captures evidence about analysis runs.
type ExecutionDetail struct {
	WorkflowPath string `json:"workflow_path,omitempty"`
	// LatestRun is the most recent run of any state, including in-progress.
	LatestRun *RunRef `json:"latest_run,omitempty"`
	// LatestCompletedRun is the most recent run that finished, and is what
	// the execution status is derived from.
	LatestCompletedRun *RunRef `json:"latest_completed_run,omitempty"`
	// LatestSuccessfulRun is the most recent successful run, which provides
	// the freshness evidence customers use for audits.
	LatestSuccessfulRun *RunRef `json:"latest_successful_run,omitempty"`
}

// RunRef is a compact reference to an Actions workflow run.
type RunRef struct {
	ID         int64      `json:"id"`
	Status     string     `json:"status,omitempty"`
	Conclusion string     `json:"conclusion,omitempty"`
	Event      string     `json:"event,omitempty"`
	HeadBranch string     `json:"head_branch,omitempty"`
	HeadSHA    string     `json:"head_sha,omitempty"`
	StartedAt  *Timestamp `json:"started_at,omitempty"`
	UpdatedAt  *Timestamp `json:"updated_at,omitempty"`
	URL        string     `json:"url,omitempty"`
	Attempt    int        `json:"attempt,omitempty"`
}

// Diagnostic is a single detected problem. Source records whether it came from
// a stable API field or from best-effort log parsing, so consumers never treat
// a scraped log line as authoritative.
type Diagnostic struct {
	Source   DiagnosticSource `json:"source"`
	Severity string           `json:"severity"`
	Code     string           `json:"code,omitempty"`
	Message  string           `json:"message"`
	Language Language         `json:"language,omitempty"`
	Excerpt  string           `json:"excerpt,omitempty"`
	URL      string           `json:"url,omitempty"`
}

// Stats records the cost of a collection so that performance regressions and
// rate limit pressure are visible in the output itself.
type Stats struct {
	APIRequests      int     `json:"api_requests"`
	GraphQLRequests  int     `json:"graphql_requests"`
	CacheHits        int     `json:"cache_hits"`
	RateLimitWaits   int     `json:"rate_limit_waits"`
	DurationSeconds  float64 `json:"duration_seconds"`
	RateLimitRemains int     `json:"rate_limit_remaining,omitempty"`
	// Incomplete is true when any organization or repository failed, meaning
	// absence of a problem in this report does not prove absence of a problem.
	Incomplete bool `json:"incomplete"`
}

// NeedsAttention reports whether a severity represents an actionable problem
// rather than an expected or benign state.
func NeedsAttention(severity Severity) bool {
	switch severity {
	case SeverityFailing, SeverityStalled, SeverityStale, SeverityDegraded:
		return true
	default:
		return false
	}
}

// PropertyValue looks up a custom property value case-insensitively.
//
// Custom property names are defined by each organization in arbitrary case
// ("Project", "PROJECT", "project"), and nobody remembers which. Requiring an
// exact match would silently report every repository as having no value.
func PropertyValue(properties map[string]string, name string) (string, bool) {
	if len(properties) == 0 || name == "" {
		return "", false
	}
	if value, ok := properties[name]; ok {
		return value, true
	}
	for key, value := range properties {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return "", false
}

// PropertyKey returns the organization's own spelling of a property name, so
// output uses the real casing rather than whatever the user typed.
func PropertyKey(properties map[string]string, name string) string {
	for key := range properties {
		if strings.EqualFold(key, name) {
			return key
		}
	}
	return name
}

// BuildSummary computes all aggregate counts for a set of repositories.
func BuildSummary(repos []Repo, groupProperty string) Summary {
	summary := Summary{
		TotalRepositories: len(repos),
		BySeverity:        map[string]int{},
		ByConfiguration:   map[string]int{},
		ByExecution:       map[string]int{},
		ByFreshness:       map[string]int{},
		ByCoverage:        map[string]int{},
	}

	// Resolve the property to the organization's own casing once, so group
	// labels match what an administrator sees in the settings UI.
	groupLabel := groupProperty
	for _, repo := range repos {
		if resolved := PropertyKey(repo.Properties, groupProperty); resolved != groupProperty {
			groupLabel = resolved
			break
		}
	}

	groups := map[string]*GroupSummary{}
	for _, repo := range repos {
		summary.BySeverity[string(repo.Status.Overall)]++
		summary.ByConfiguration[string(repo.Status.Configuration)]++
		summary.ByExecution[string(repo.Status.Execution)]++
		summary.ByFreshness[string(repo.Status.Freshness)]++
		summary.ByCoverage[string(repo.Status.Coverage)]++
		if NeedsAttention(repo.Status.Overall) {
			summary.NeedsAttention++
		}

		if groupProperty == "" {
			continue
		}
		value, _ := PropertyValue(repo.Properties, groupProperty)
		if value == "" {
			value = "(not set)"
		}
		group, ok := groups[value]
		if !ok {
			group = &GroupSummary{Property: groupLabel, Value: value, BySeverity: map[string]int{}}
			groups[value] = group
		}
		group.Repositories++
		group.BySeverity[string(repo.Status.Overall)]++
		if NeedsAttention(repo.Status.Overall) {
			group.NeedsAttention++
		}
	}

	if len(groups) > 0 {
		summary.Groups = make([]GroupSummary, 0, len(groups))
		for _, group := range groups {
			summary.Groups = append(summary.Groups, *group)
		}
		sort.Slice(summary.Groups, func(i, j int) bool {
			if summary.Groups[i].NeedsAttention != summary.Groups[j].NeedsAttention {
				return summary.Groups[i].NeedsAttention > summary.Groups[j].NeedsAttention
			}
			return summary.Groups[i].Value < summary.Groups[j].Value
		})
	}

	return summary
}

// BuildOrgReports aggregates per-organization counts.
func BuildOrgReports(repos []Repo) []OrgReport {
	index := map[string]*OrgReport{}
	for _, repo := range repos {
		org, ok := index[repo.Organization]
		if !ok {
			org = &OrgReport{Login: repo.Organization, BySeverity: map[string]int{}}
			index[repo.Organization] = org
		}
		org.TotalRepositories++
		org.BySeverity[string(repo.Status.Overall)]++
		if NeedsAttention(repo.Status.Overall) {
			org.NeedsAttention++
		}
	}

	reports := make([]OrgReport, 0, len(index))
	for _, org := range index {
		reports = append(reports, *org)
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].Login < reports[j].Login })
	return reports
}

// SortRepos orders repositories by urgency first so the most important rows
// appear at the top of any output, then alphabetically for stability.
func SortRepos(repos []Repo) {
	sort.SliceStable(repos, func(i, j int) bool {
		left, right := repos[i], repos[j]
		if left.Status.Overall != right.Status.Overall {
			return left.Status.Overall.Rank() < right.Status.Overall.Rank()
		}
		if left.Organization != right.Organization {
			return left.Organization < right.Organization
		}
		return left.Name < right.Name
	})
}
