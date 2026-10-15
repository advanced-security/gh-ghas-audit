// This file defines the versioned data contract produced by the Dependabot /
// software composition analysis (SCA) health collector. It is a sibling to
// Report/Repo (code scanning), not an extension of them: Dependabot health is
// judged on entirely different evidence (dependency graph manifests,
// Dependabot alerts, dependabot.yml, pull request health), so a shared
// per-repository shape would carry many fields that never apply to either
// side. Generic types that are not code-scanning-specific (Severity,
// ToolInfo, Scope, Stats, OrgReport, Timestamp) are reused directly.
package model

import "sort"

// DependabotSchemaVersion identifies the shape of the Dependabot JSON/NDJSON
// report. Consumers should check this before parsing.
const DependabotSchemaVersion = "1.0.0"

// DependabotReport is the top-level, versioned document emitted by a
// Dependabot/SCA health collection.
type DependabotReport struct {
	SchemaVersion string             `json:"schema_version"`
	GeneratedAt   Timestamp          `json:"generated_at"`
	Tool          ToolInfo           `json:"tool"`
	Scope         Scope              `json:"scope"`
	Settings      DependabotSettings `json:"settings"`
	Summary       DependabotSummary  `json:"summary"`
	Organizations []OrgReport        `json:"organizations"`
	Repositories  []DependabotRepo   `json:"repositories"`
	// Warnings records non-fatal collection problems, such as an organization
	// that could not be read. Their presence means the report is incomplete.
	Warnings []string `json:"warnings,omitempty"`
	Stats    Stats    `json:"stats"`
}

// DependabotSettings records the thresholds and options that produced the
// results, so a stored report is self-describing.
type DependabotSettings struct {
	SkipArchived          bool       `json:"skip_archived"`
	SkipForks             bool       `json:"skip_forks"`
	SecurityConfiguration string     `json:"security_configuration,omitempty"`
	Concurrency           int        `json:"concurrency"`
	Match                 []string   `json:"match,omitempty"`
	Exclude               []string   `json:"exclude,omitempty"`
	Visibility            []string   `json:"visibility,omitempty"`
	Status                []Severity `json:"status,omitempty"`
	// ScanDepth records how much evidence this report is based on, so a
	// stored artifact states what it did and did not check.
	ScanDepth string `json:"scan_depth,omitempty"`
	// DependencyReviewCheckPattern is the (case-insensitive, substring)
	// pattern used to recognize a "dependency review" required status check
	// among a repository's effective ruleset rules. There is no native
	// ruleset rule type for dependency review; it is always enforced through
	// a required status check referencing a job name that varies by
	// configuration, so this must be configurable rather than fixed.
	DependencyReviewCheckPattern string `json:"dependency_review_check_pattern,omitempty"`
}

// DependabotSummary holds aggregate counts for an entire report.
type DependabotSummary struct {
	TotalRepositories int            `json:"total_repositories"`
	BySeverity        map[string]int `json:"by_severity"`
	// NeedsAttention counts repositories whose severity is actionable.
	NeedsAttention int `json:"needs_attention"`
}

// DependabotRepo is the per-repository record: the unit customers triage.
type DependabotRepo struct {
	Organization   string     `json:"organization"`
	Name           string     `json:"name"`
	FullName       string     `json:"full_name"`
	URL            string     `json:"url"`
	Visibility     string     `json:"visibility"`
	Archived       bool       `json:"archived"`
	Fork           bool       `json:"fork"`
	DefaultBranch  string     `json:"default_branch"`
	PushedAt       *Timestamp `json:"pushed_at,omitempty"`
	LastActivityAt *Timestamp `json:"last_activity_at,omitempty"`
	// TemporarySecurityAdvisoryFork records whether this repository is one
	// of GitHub's temporary private forks, automatically created when a
	// maintainer starts drafting a fix for a security advisory. There is no
	// dedicated API field marking this; it is identified by GitHub's own
	// documented repository naming convention for these forks (the source
	// repository's name followed by "-ghsa-" and the advisory's GHSA
	// identifier suffix, for example "example-repo-ghsa-4xcm-h78r-r3ww").
	// A non-empty temp_clone_token or a private/internal visibility were
	// both considered and rejected as signals: GitHub populates
	// temp_clone_token, and marks the repository private or internal, for
	// every ordinary private/internal repository, not just these forks, so
	// either would misidentify nearly all of them. These forks have a
	// deliberately restricted API surface: for example, the rules and
	// rulesets endpoints always return 404 regardless of any ruleset
	// actually configured on the real repository. Dependency review
	// enforcement is not evaluated for such a repository (see
	// collectDependencyReview) rather than being recorded as a collection
	// error, since the 404 is an expected, structural property of the fork,
	// not missing or incomplete evidence.
	TemporarySecurityAdvisoryFork bool `json:"temporary_security_advisory_fork,omitempty"`

	Status DependabotStatus `json:"status"`

	DependencyGraph  DependencyGraphDetail  `json:"dependency_graph"`
	Alerts           AlertsDetail           `json:"alerts"`
	VersionUpdates   VersionUpdatesDetail   `json:"version_updates"`
	PullRequests     PullRequestsDetail     `json:"pull_requests"`
	DependencyReview DependencyReviewDetail `json:"dependency_review"`

	Properties map[string]string `json:"properties,omitempty"`
	// Errors records per-repository collection failures. A repository with
	// errors has incomplete data and must not be read as healthy.
	Errors []string `json:"errors,omitempty"`
}

// FeatureState describes a simple on/off/unset GitHub feature toggle.
type FeatureState string

const (
	// FeatureEnabled means the feature is turned on.
	FeatureEnabled FeatureState = "enabled"
	// FeatureDisabled means the feature is turned off.
	FeatureDisabled FeatureState = "disabled"
	// FeatureNotSet means the feature has never been explicitly configured.
	FeatureNotSet FeatureState = "not_set"
	// FeatureNotEvaluated means the scan depth did not gather this evidence.
	FeatureNotEvaluated FeatureState = "not-evaluated"
	// FeatureUnknown means the state could not be determined, usually a
	// permissions problem: security_and_analysis is only visible to repository
	// admins, owners or security managers.
	FeatureUnknown FeatureState = "unknown"
)

// VersionUpdatesState describes whether dependabot.yml version updates are
// configured and actually able to run.
type VersionUpdatesState string

const (
	// VersionUpdatesConfigured means a parseable dependabot.yml exists.
	VersionUpdatesConfigured VersionUpdatesState = "configured"
	// VersionUpdatesNotConfigured means no dependabot.yml was found.
	VersionUpdatesNotConfigured VersionUpdatesState = "not-configured"
	// VersionUpdatesParseError means dependabot.yml exists but could not be
	// parsed as YAML, which silently disables every update in the file.
	VersionUpdatesParseError VersionUpdatesState = "parse-error"
	// VersionUpdatesPausedInactivity means GitHub has paused automated
	// Dependabot activity after roughly 90 days without interaction. This is
	// primarily determined authoritatively via the "Check if Dependabot
	// security updates are enabled for a repository" REST endpoint's
	// "paused" field, which is populated regardless of whether the
	// repository has any open Dependabot pull requests. When that check is
	// unavailable, an open Dependabot pull request carrying the
	// "dependabot-paused" label is used as a best-effort fallback; absence
	// of this state in that fallback path is not proof updates are running.
	VersionUpdatesPausedInactivity VersionUpdatesState = "paused-inactivity"
	// VersionUpdatesNotEvaluated means the scan depth did not read dependabot.yml.
	VersionUpdatesNotEvaluated VersionUpdatesState = "not-evaluated"
	// VersionUpdatesUnknown means the state could not be determined.
	VersionUpdatesUnknown VersionUpdatesState = "unknown"
)

// PullRequestHealthState summarizes the open Dependabot pull requests for a
// repository.
type PullRequestHealthState string

const (
	// PRHealthHealthy means open Dependabot pull requests, if any, have
	// passing checks and are not backlogged.
	PRHealthHealthy PullRequestHealthState = "healthy"
	// PRHealthFailingChecks means at least one open Dependabot pull request
	// has a failing combined status.
	PRHealthFailingChecks PullRequestHealthState = "failing-checks"
	// PRHealthBacklogged means open, non-security Dependabot pull requests
	// are at or near the configured (or default) open-pull-requests-limit,
	// which stops any further version-update pull requests from opening.
	// Security-update pull requests are never limited and are excluded from
	// this count.
	PRHealthBacklogged PullRequestHealthState = "backlogged"
	// PRHealthNone means no open Dependabot pull requests were found.
	PRHealthNone PullRequestHealthState = "none-open"
	// PRHealthNotEvaluated means the scan depth did not inspect pull requests.
	PRHealthNotEvaluated PullRequestHealthState = "not-evaluated"
	// PRHealthUnknown means pull request health could not be determined.
	PRHealthUnknown PullRequestHealthState = "unknown"
)

// DependencyGraphCoverageState describes whether ecosystems that need more
// than static manifest parsing to produce transitive dependencies (Maven and
// Gradle need a build-time submission action; npm/yarn/pnpm lockfiles and
// similar are captured by static parsing alone) actually have transitive
// dependency data in the graph. This is one of the strongest, most direct
// signals for "the dependency graph is missing build-time information": a
// Maven/Gradle manifest with zero transitive-relationship dependencies is
// concrete evidence that only the manifest was parsed, not a real build.
type DependencyGraphCoverageState string

const (
	// GraphCoverageComplete means every manifest that needs build-time/
	// lockfile resolution to show transitive dependencies actually has them,
	// or no such manifest exists in the repository.
	GraphCoverageComplete DependencyGraphCoverageState = "complete"
	// GraphCoveragePartial means at least one manifest that needs build-time
	// resolution shows only direct dependencies, and no auto-submission
	// mechanism was detected to explain it.
	GraphCoveragePartial DependencyGraphCoverageState = "partial"
	// GraphCoverageMitigated means a transitive-dependency gap was detected,
	// but a known dependency-submission workflow/action was also found, so
	// the gap is most likely already closed by a separate submission job
	// rather than by this repository's default graph parsing.
	GraphCoverageMitigated DependencyGraphCoverageState = "mitigated"
	// GraphCoverageNotApplicable means no manifests requiring build-time
	// resolution were found.
	GraphCoverageNotApplicable DependencyGraphCoverageState = "not-applicable"
	// GraphCoverageNotEvaluated means the scan depth did not gather manifest
	// evidence.
	GraphCoverageNotEvaluated DependencyGraphCoverageState = "not-evaluated"
	// GraphCoverageUnknown means coverage could not be determined.
	GraphCoverageUnknown DependencyGraphCoverageState = "unknown"
)

// DependencyReviewState describes whether a pull-request-blocking check
// enforcing dependency review was found among a branch's effective rules.
type DependencyReviewState string

const (
	// DependencyReviewEnforced means a required status check matching the
	// configured pattern was found.
	DependencyReviewEnforced DependencyReviewState = "enforced"
	// DependencyReviewNotEnforced means no matching required status check
	// was found among the branch's effective rules.
	DependencyReviewNotEnforced DependencyReviewState = "not-enforced"
	// DependencyReviewNotEvaluated means the scan depth did not check rules.
	DependencyReviewNotEvaluated DependencyReviewState = "not-evaluated"
	// DependencyReviewUnknown means enforcement could not be determined.
	DependencyReviewUnknown DependencyReviewState = "unknown"
)

// DependabotStatus holds the independent health dimensions for a repository,
// following the same pattern as code scanning's Status: dimensions stay
// separate because "graph is off" and "PRs are backlogged" are different
// problems with different fixes, and Overall is a derived roll-up for sorting
// and summary counts only.
type DependabotStatus struct {
	Overall Severity `json:"overall"`

	DependencyGraph           FeatureState                 `json:"dependency_graph"`
	DependencyGraphCoverage   DependencyGraphCoverageState `json:"dependency_graph_coverage"`
	DependabotAlerts          FeatureState                 `json:"dependabot_alerts"`
	DependabotSecurityUpdates FeatureState                 `json:"dependabot_security_updates"`
	VersionUpdates            VersionUpdatesState          `json:"version_updates"`
	PullRequestHealth         PullRequestHealthState       `json:"pull_request_health"`
	DependencyReview          DependencyReviewState        `json:"dependency_review"`

	// Incomplete records that some evidence could not be collected for this
	// repository. A repository with incomplete evidence is never reported as
	// healthy.
	Incomplete bool `json:"incomplete,omitempty"`
	// Reasons explains, in human-readable form, why Overall was chosen.
	Reasons []string `json:"reasons,omitempty"`
}

// DependencyGraphDetail captures evidence about the completeness of the
// dependency graph, gathered from the dependencyGraphManifests GraphQL field.
type DependencyGraphDetail struct {
	Evaluated      bool     `json:"evaluated"`
	TotalManifests int      `json:"total_manifests,omitempty"`
	Ecosystems     []string `json:"ecosystems,omitempty"`
	// UnparseableManifests lists manifest filenames the graph could not parse
	// at all (parseable=false).
	UnparseableManifests []string `json:"unparseable_manifests,omitempty"`
	// OversizedManifests lists manifest filenames that exceeded the graph's
	// maximum manifest size and were only partially processed.
	OversizedManifests []string `json:"oversized_manifests,omitempty"`
	// ManifestsMissingTransitive lists manifest filenames, for ecosystems
	// that need build-time or lockfile resolution to see transitive
	// dependencies (Maven, Gradle, NuGet), where none of the recorded
	// dependencies have relationship=transitive (every one is direct or, for
	// an unresolved manifest GitHub could not classify at all, unknown).
	// This is the "partial coverage" gap: the manifest was statically
	// parsed, but nothing resolved its actual dependency tree.
	ManifestsMissingTransitive []string `json:"manifests_missing_transitive,omitempty"`
	// AutoSubmissionDetected records whether a known build-time dependency
	// submission mechanism was found: either a workflow file referencing a
	// known Action (Maven, Gradle, or Component Detection
	// dependency-submission actions), or, only when there is no remaining
	// ManifestsMissingTransitive gap to explain, a non-baseline tool named in
	// the repository's SBOM export (which also reveals GitHub's native,
	// no-workflow-file "Automatic Dependency Submission" repository toggle).
	// This is checked whenever the repository has at least one
	// build-time-resolution manifest (Maven, Gradle, or NuGet) — both to
	// explain or close a ManifestsMissingTransitive gap, and, when there is
	// no gap, to positively confirm what is already keeping coverage
	// complete.
	AutoSubmissionDetected bool `json:"auto_submission_detected,omitempty"`
	// AutoSubmissionAction names the workflow action reference or SBOM tool
	// name that matched, so the finding can be verified without re-deriving
	// it.
	AutoSubmissionAction string `json:"auto_submission_action,omitempty"`
}

// AlertsDetail summarizes open Dependabot (vulnerability) alerts.
type AlertsDetail struct {
	Evaluated    bool `json:"evaluated"`
	OpenTotal    int  `json:"open_total"`
	OpenCritical int  `json:"open_critical"`
	OpenHigh     int  `json:"open_high"`
	OpenMedium   int  `json:"open_medium"`
	OpenLow      int  `json:"open_low"`
	// OpenMalware counts open alerts whose security advisory is classified
	// as "malware" rather than "general": these flag a dependency that is
	// itself malicious (for example a compromised or typosquatted package),
	// not merely vulnerable, and are reported separately because they
	// typically warrant immediate removal rather than an ordinary patch
	// update. A malware alert is also counted in the matching severity
	// field above; this is not an additional, non-overlapping count.
	OpenMalware    int        `json:"open_malware"`
	OldestOpen     *Timestamp `json:"oldest_open,omitempty"`
	OldestOpenDays *int       `json:"oldest_open_days,omitempty"`
}

// VersionUpdatesDetail captures dependabot.yml configuration evidence.
type VersionUpdatesDetail struct {
	ConfigPath     string   `json:"config_path,omitempty"`
	Ecosystems     []string `json:"ecosystems,omitempty"`
	TargetBranches []string `json:"target_branches,omitempty"`
	// EcosystemLimits sums each configured update block's effective
	// open-pull-requests-limit (GitHub's documented default of 5 when a
	// block does not set one explicitly) per package-ecosystem value. This
	// is an approximation, not an exact per-block accounting: multiple
	// blocks for the same ecosystem (for example two separate npm
	// directories) have their limits summed here, but an open pull request
	// is not individually attributed back to the specific block that opened
	// it, so a saturated block can still be masked by headroom in a
	// different, unsaturated block for the same ecosystem.
	EcosystemLimits map[string]int `json:"ecosystem_limits,omitempty"`
	// UncoveredEcosystems lists ecosystems configured for version updates
	// that the dependency graph / Dependabot alerts do not track at all
	// (for example docker, terraform, helm). Version updates still run for
	// these, but there is no vulnerability alert coverage to expect.
	UncoveredEcosystems []string `json:"uncovered_ecosystems,omitempty"`
	// RegistriesConfigured lists top-level private registry names declared
	// in dependabot.yml.
	RegistriesConfigured []string `json:"registries_configured,omitempty"`
	// RegistriesMissingSecret lists configured registries whose credential
	// keys do not correspond to any org or repo Dependabot secret found.
	// This is a best-effort proxy: no public API reports Dependabot job
	// failures directly, so a missing secret is treated as a likely (not
	// certain) misconfiguration.
	RegistriesMissingSecret []string `json:"registries_missing_secret,omitempty"`
	ParseError              string   `json:"parse_error,omitempty"`
}

// PullRequestsDetail captures evidence about open Dependabot pull requests.
type PullRequestsDetail struct {
	Evaluated bool `json:"evaluated"`
	Open      int  `json:"open"`
	// OpenSecurityUpdates and OpenVersionUpdates split Open by update type.
	// A pull request is counted as a security update only when it is
	// reachable from an open vulnerability alert's dependabotUpdate.pullRequest
	// GraphQL field; every other open Dependabot pull request is a version
	// update. GitHub's documented open-pull-requests-limit only throttles
	// version updates, so backlog detection is evaluated against
	// OpenVersionUpdates, not Open.
	OpenSecurityUpdates int `json:"open_security_updates"`
	OpenVersionUpdates  int `json:"open_version_updates"`
	// OpenFailingChecks counts open Dependabot pull requests whose combined
	// status is failure or error.
	OpenFailingChecks int        `json:"open_failing_checks"`
	OldestOpen        *Timestamp `json:"oldest_open,omitempty"`
	OldestOpenDays    *int       `json:"oldest_open_days,omitempty"`
	// PausedForInactivity is a best-effort signal: at least one open pull
	// request carries the "dependabot-paused" label.
	PausedForInactivity bool `json:"paused_for_inactivity,omitempty"`
}

// DependencyReviewDetail captures evidence about whether a required status
// check enforcing dependency review was found among a branch's effective
// ruleset rules.
type DependencyReviewDetail struct {
	Evaluated           bool   `json:"evaluated"`
	Branch              string `json:"branch,omitempty"`
	MatchedCheckContext string `json:"matched_check_context,omitempty"`
	Pattern             string `json:"pattern,omitempty"`
}

// dependabotSeverityRank mirrors code scanning's severity precedence but is
// evaluated independently, because the two domains derive Overall from
// entirely different evidence.
func dependabotClassify(status *DependabotStatus) {
	status.Overall, status.Reasons = classifyDependabot(status)
	if status.Incomplete && status.Overall == SeverityHealthy {
		status.Overall = SeverityUnknown
		status.Reasons = []string{
			"some evidence could not be collected, so this repository cannot be confirmed healthy",
		}
	}
}

// classifyDependabot derives the roll-up severity from the individual
// dimensions using a fixed precedence, so identical inputs always produce
// identical output.
//
// Precedence: dependency graph disabled, failing PR checks, paused for
// inactivity, PR backlog, dependency review not enforced, dependency graph
// gaps, alerts disabled, not configured at all, healthy.
func classifyDependabot(status *DependabotStatus) (Severity, []string) {
	if status.DependencyGraph == FeatureDisabled {
		return SeverityStalled, []string{
			"the dependency graph is disabled, so no dependency or alert evidence can be produced",
		}
	}

	if status.PullRequestHealth == PRHealthFailingChecks {
		return SeverityFailing, []string{"one or more open Dependabot pull requests have failing checks"}
	}

	if status.VersionUpdates == VersionUpdatesPausedInactivity {
		return SeverityStalled, []string{
			"Dependabot updates are paused for inactivity (GitHub pauses automated Dependabot activity after roughly 90 days without interaction)",
		}
	}

	if status.PullRequestHealth == PRHealthBacklogged {
		return SeverityDegraded, []string{
			"open Dependabot pull requests are at or near the version-update limit, blocking new pull requests",
		}
	}

	if status.DependencyReview == DependencyReviewNotEnforced {
		return SeverityDegraded, []string{
			"no required status check matching the dependency review pattern was found for this branch",
		}
	}

	if status.DependencyGraphCoverage == GraphCoveragePartial {
		return SeverityDegraded, []string{
			"one or more manifests show only direct dependencies for an ecosystem that needs build-time " +
				"or lockfile resolution to see transitive dependencies, and no auto-submission workflow was found",
		}
	}

	var reasons []string
	if status.VersionUpdates == VersionUpdatesParseError {
		reasons = append(reasons, "dependabot.yml exists but could not be parsed")
	}

	if len(reasons) > 0 {
		return SeverityDegraded, reasons
	}

	if status.DependabotAlerts == FeatureDisabled {
		return SeverityDegraded, []string{"Dependabot alerts are disabled"}
	}

	if status.DependencyGraph == FeatureNotSet && status.DependabotAlerts != FeatureEnabled &&
		status.VersionUpdates == VersionUpdatesNotConfigured {
		return SeverityNotConfigured, []string{"no Dependabot or dependency graph features are configured"}
	}

	if status.DependencyGraph == FeatureUnknown && status.DependabotAlerts == FeatureUnknown {
		return SeverityUnknown, []string{"Dependabot configuration could not be read for this repository"}
	}

	// Configuration-only depth gathers no runtime evidence (open alerts, pull
	// request health, manifest coverage), so a repository can be reported as
	// configured but never as healthy. Dependency review enforcement is
	// deliberately excluded from this guard: it is only ever checked at
	// diagnostics depth (collectDependencyReview), so DependencyReviewNotEvaluated
	// is the expected, healthy-compatible state at config and health depth,
	// not a sign that evidence is missing.
	if status.DependencyGraph == FeatureNotEvaluated ||
		status.PullRequestHealth == PRHealthNotEvaluated ||
		status.DependencyGraphCoverage == GraphCoverageNotEvaluated {
		return SeverityUnknown, []string{
			"only configuration was read at this scan depth, so Dependabot health was not evaluated",
		}
	}

	return SeverityHealthy, nil
}

// ClassifyDependabot is the exported entry point mirroring code scanning's
// Classify, so the collector never needs to reach into this file's internals.
func ClassifyDependabot(status *DependabotStatus) {
	dependabotClassify(status)
}

// BuildDependabotSummary computes aggregate counts for a set of repositories.
func BuildDependabotSummary(repos []DependabotRepo) DependabotSummary {
	summary := DependabotSummary{
		TotalRepositories: len(repos),
		BySeverity:        map[string]int{},
	}
	for _, repo := range repos {
		summary.BySeverity[string(repo.Status.Overall)]++
		if NeedsAttention(repo.Status.Overall) {
			summary.NeedsAttention++
		}
	}
	return summary
}

// BuildDependabotOrgReports aggregates per-organization counts.
func BuildDependabotOrgReports(repos []DependabotRepo) []OrgReport {
	index := map[string]*OrgReport{}
	var order []string
	for _, repo := range repos {
		org, ok := index[repo.Organization]
		if !ok {
			org = &OrgReport{Login: repo.Organization, BySeverity: map[string]int{}}
			index[repo.Organization] = org
			order = append(order, repo.Organization)
		}
		org.TotalRepositories++
		org.BySeverity[string(repo.Status.Overall)]++
		if NeedsAttention(repo.Status.Overall) {
			org.NeedsAttention++
		}
	}

	reports := make([]OrgReport, 0, len(index))
	for _, login := range order {
		reports = append(reports, *index[login])
	}
	return reports
}

// SortDependabotRepos orders repositories by urgency first, then
// alphabetically for stability, mirroring code scanning's SortRepos.
func SortDependabotRepos(repos []DependabotRepo) {
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
