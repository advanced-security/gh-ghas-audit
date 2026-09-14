// Package model contains the versioned data contract produced by the
// code scanning status collector, together with the deterministic rules used
// to classify repository health.
package model

// SchemaVersion identifies the shape of the JSON/NDJSON report. Consumers
// (dashboards, spreadsheets, other tools) should check this before parsing.
const SchemaVersion = "1.0.0"

// ConfigurationStatus describes whether code scanning is set up for a
// repository, independently of whether any scan has actually succeeded.
type ConfigurationStatus string

const (
	// ConfigConfigured means default setup reports state "configured".
	ConfigConfigured ConfigurationStatus = "configured"
	// ConfigNotConfigured means default setup is available but switched off.
	ConfigNotConfigured ConfigurationStatus = "not-configured"
	// ConfigAdvancedSetup means default setup is off and CodeQL uses a
	// repository-managed Actions workflow.
	ConfigAdvancedSetup ConfigurationStatus = "advanced-setup"
	// ConfigExternalCI means CodeQL analyses from a non-Actions CI system were
	// detected. Their configuration and health are not evaluated.
	ConfigExternalCI ConfigurationStatus = "external-ci"
	// ConfigAttaching means a security configuration is still being applied.
	ConfigAttaching ConfigurationStatus = "attaching"
	// ConfigUpdating means a security configuration is being updated.
	ConfigUpdating ConfigurationStatus = "updating"
	// ConfigAttachFailed means a security configuration failed to attach.
	ConfigAttachFailed ConfigurationStatus = "attach-failed"
	// ConfigUnavailable means the API refused the request, typically because
	// code security is not licensed or enabled for the repository.
	ConfigUnavailable ConfigurationStatus = "unavailable"
	// ConfigUnknown means the state could not be determined.
	ConfigUnknown ConfigurationStatus = "unknown"
)

// ExecutionStatus describes the selected CodeQL workflow and its most relevant
// analysis run on the repository default branch.
type ExecutionStatus string

const (
	// ExecSuccess means the latest completed run succeeded.
	ExecSuccess ExecutionStatus = "success"
	// ExecFailure means the latest completed run failed.
	ExecFailure ExecutionStatus = "failure"
	// ExecTimedOut means the latest completed run timed out.
	ExecTimedOut ExecutionStatus = "timed-out"
	// ExecCancelled means the latest completed run was cancelled.
	ExecCancelled ExecutionStatus = "cancelled"
	// ExecActionRequired means the latest completed run needs intervention.
	ExecActionRequired ExecutionStatus = "action-required"
	// ExecStartupFailure means the run could not start, usually a workflow or
	// runner configuration problem.
	ExecStartupFailure ExecutionStatus = "startup-failure"
	// ExecInProgress means a run is currently executing.
	ExecInProgress ExecutionStatus = "in-progress"
	// ExecQueued means a run is queued or waiting for a runner.
	ExecQueued ExecutionStatus = "queued"
	// ExecDisabled means the selected workflow is disabled and cannot scan.
	ExecDisabled ExecutionStatus = "disabled"
	// ExecNoWorkflow means default setup is configured but the managed CodeQL
	// workflow does not exist. Scanning has never been provisioned.
	ExecNoWorkflow ExecutionStatus = "no-workflow"
	// ExecNoCompletedRun means the workflow exists but has never completed on
	// the default branch. This is the "configured but silently not scanning"
	// case that a plain success/failure check misses.
	ExecNoCompletedRun ExecutionStatus = "no-completed-run"
	// ExecNotApplicable means execution was not evaluated.
	ExecNotApplicable ExecutionStatus = "not-applicable"
	// ExecNotEvaluated means execution evidence was deliberately not gathered,
	// because the scan depth did not ask for it.
	ExecNotEvaluated ExecutionStatus = "not-evaluated"
	// ExecUnknown means execution could not be determined.
	ExecUnknown ExecutionStatus = "unknown"
)

// FreshnessStatus describes whether successful scan evidence is recent enough
// to satisfy the configured staleness threshold.
type FreshnessStatus string

const (
	// FreshCurrent means successful evidence is within the threshold.
	FreshCurrent FreshnessStatus = "current"
	// FreshStale means the newest successful evidence is older than allowed.
	FreshStale FreshnessStatus = "stale"
	// FreshNever means no successful scan evidence exists at all.
	FreshNever FreshnessStatus = "never-scanned"
	// FreshNotApplicable means freshness was not evaluated.
	FreshNotApplicable FreshnessStatus = "not-applicable"
	// FreshNotEvaluated means freshness evidence was deliberately not
	// gathered, because the scan depth did not ask for it.
	FreshNotEvaluated FreshnessStatus = "not-evaluated"
	// FreshUnknown means freshness could not be determined.
	FreshUnknown FreshnessStatus = "unknown"
)

// CoverageStatus describes how completely the languages present in a
// repository are actually being analyzed.
type CoverageStatus string

const (
	// CoverageComplete means every supported detected language is configured
	// and analyzed successfully.
	CoverageComplete CoverageStatus = "complete"
	// CoveragePartial means some configured languages are not producing
	// successful analyses.
	CoveragePartial CoverageStatus = "partial"
	// CoverageGap means supported languages exist in the repository but are
	// not configured for analysis at all.
	CoverageGap CoverageStatus = "gap"
	// CoverageNoSupportedLanguages means nothing in the repository can be
	// analyzed by CodeQL. This is expected, not a failure.
	CoverageNoSupportedLanguages CoverageStatus = "no-supported-languages"
	// CoverageNotApplicable means coverage was not evaluated.
	CoverageNotApplicable CoverageStatus = "not-applicable"
	// CoverageUnknown means coverage could not be determined.
	CoverageUnknown CoverageStatus = "unknown"
)

// DiagnosticSource records how much confidence a diagnostic carries.
type DiagnosticSource string

const (
	// SourceAPI marks a diagnostic derived from stable, documented API fields.
	SourceAPI DiagnosticSource = "api"
	// SourceLog marks a best-effort diagnostic parsed from Actions logs. Log
	// text is unstructured and can change without notice.
	SourceLog DiagnosticSource = "log"
)

// Severity is the single roll-up value derived from the individual status
// dimensions. It exists for sorting and summary counts; the dimensions remain
// authoritative for triage.
type Severity string

const (
	// SeverityFailing means the most recent analysis run failed outright.
	SeverityFailing Severity = "failing"
	// SeverityStalled means scanning is configured but is not running.
	SeverityStalled Severity = "stalled"
	// SeverityStale means scanning ran successfully but not recently enough.
	SeverityStale Severity = "stale"
	// SeverityDegraded means scanning succeeded but coverage is incomplete or
	// a warning was detected.
	SeverityDegraded Severity = "degraded"
	// SeverityInProgress means a run is currently executing.
	SeverityInProgress Severity = "in-progress"
	// SeverityHealthy means scanning is configured, current, and complete.
	SeverityHealthy Severity = "healthy"
	// SeverityNotConfigured means code scanning is not enabled here.
	SeverityNotConfigured Severity = "not-configured"
	// SeverityNotApplicable means the repository has no analyzable content.
	SeverityNotApplicable Severity = "not-applicable"
	// SeverityUnavailable means the repository could not be inspected.
	SeverityUnavailable Severity = "unavailable"
	// SeverityUnknown means classification was not possible.
	SeverityUnknown Severity = "unknown"
)

// severityRank orders severities from most to least operationally urgent.
var severityRank = map[Severity]int{
	SeverityFailing:       0,
	SeverityStalled:       1,
	SeverityStale:         2,
	SeverityDegraded:      3,
	SeverityInProgress:    4,
	SeverityHealthy:       5,
	SeverityNotConfigured: 6,
	SeverityNotApplicable: 7,
	SeverityUnavailable:   8,
	SeverityUnknown:       9,
}

// Rank returns the sort order of a severity, lowest being most urgent.
func (s Severity) Rank() int {
	if rank, ok := severityRank[s]; ok {
		return rank
	}
	return len(severityRank)
}

// AllSeverities lists every severity in urgency order. Used for summary
// output and for validating user-supplied filters.
func AllSeverities() []Severity {
	return []Severity{
		SeverityFailing,
		SeverityStalled,
		SeverityStale,
		SeverityDegraded,
		SeverityInProgress,
		SeverityHealthy,
		SeverityNotConfigured,
		SeverityNotApplicable,
		SeverityUnavailable,
		SeverityUnknown,
	}
}

// ParseSeverity resolves a user-supplied severity name. It accepts both the
// canonical hyphenated form and an underscore variant for convenience.
func ParseSeverity(value string) (Severity, bool) {
	normalized := Severity(normalizeToken(value))
	for _, candidate := range AllSeverities() {
		if candidate == normalized {
			return candidate, true
		}
	}
	return SeverityUnknown, false
}

// ExecutionFailed reports whether an execution status represents a run that
// completed unsuccessfully, as opposed to one that never ran.
func ExecutionFailed(status ExecutionStatus) bool {
	switch status {
	case ExecFailure, ExecTimedOut, ExecCancelled, ExecActionRequired, ExecStartupFailure:
		return true
	default:
		return false
	}
}

// ExecutionRunning reports whether a run is currently active.
func ExecutionRunning(status ExecutionStatus) bool {
	return status == ExecInProgress || status == ExecQueued
}

// ExecutionStalled reports whether configured scanning cannot run or has never
// completed.
func ExecutionStalled(status ExecutionStatus) bool {
	return status == ExecNoWorkflow || status == ExecNoCompletedRun || status == ExecDisabled
}

// Status holds the independent health dimensions for a repository. Keeping
// these separate is deliberate: a repository can have a green workflow run and
// still be missing a language, and "never scanned" is a different problem from
// "scan failed".
type Status struct {
	Overall       Severity            `json:"overall"`
	Configuration ConfigurationStatus `json:"configuration"`
	Execution     ExecutionStatus     `json:"execution"`
	Freshness     FreshnessStatus     `json:"freshness"`
	Coverage      CoverageStatus      `json:"coverage"`
	// Activity records the scan schedule the repository is on, which decides
	// the staleness threshold applied to it.
	Activity Activity `json:"activity,omitempty"`
	// StaleAfter is the threshold that was applied, so a stale verdict can be
	// explained without re-deriving it.
	StaleAfter string `json:"stale_after,omitempty"`
	// Incomplete records that some evidence could not be collected for this
	// repository. A repository with incomplete evidence is never reported as
	// healthy, because absence of a detected problem would not mean absence of
	// a problem.
	Incomplete bool `json:"incomplete,omitempty"`
	// Reasons explains, in human-readable form, why Overall was chosen.
	Reasons []string `json:"reasons,omitempty"`
}

// Classify derives the roll-up severity from the individual dimensions using a
// fixed precedence, so that identical inputs always produce identical output.
//
// Precedence: failing, stalled or attach-failed, stale, degraded coverage or
// warning, in progress, healthy, then the non-actionable states.
func Classify(status *Status, hasWarning bool) {
	status.Overall, status.Reasons = classify(status, hasWarning)

	// A clean verdict may only be given on complete evidence.
	if status.Incomplete && status.Overall == SeverityHealthy {
		status.Overall = SeverityUnknown
		status.Reasons = []string{
			"some evidence could not be collected, so this repository cannot be confirmed healthy",
		}
	}
}

// staleReason explains a stale verdict in terms of the schedule the repository
// is actually on, so a monthly-scanned repository is not mistaken for one that
// missed a weekly scan.
func staleReason(status *Status) string {
	threshold := status.StaleAfter
	if threshold == "" {
		threshold = "the configured threshold"
	}
	if status.Activity == ActivityInactive {
		return "no successful analysis within " + threshold +
			"; this repository has had no recent pushes, so GitHub scans it monthly at most"
	}
	return "no successful analysis within " + threshold
}

// IsScanning reports whether a configuration status means CodeQL is actually
// set up to run, by either mechanism. Advanced setup counts: it is evaluated
// like default setup, so it must be presented like it too.
func IsScanning(status ConfigurationStatus) bool {
	switch status {
	case ConfigConfigured, ConfigAttachFailed, ConfigAdvancedSetup:
		return true
	default:
		return false
	}
}

// setupNoun names the mechanism doing the scanning, so a message about an
// advanced setup repository does not blame default setup.
func setupNoun(status *Status) string {
	if status.Configuration == ConfigAdvancedSetup {
		return "an advanced setup workflow"
	}
	return "default setup"
}

func classify(status *Status, hasWarning bool) (Severity, []string) {
	var reasons []string

	if ExecutionFailed(status.Execution) {
		return SeverityFailing, []string{"latest analysis run reported " + string(status.Execution)}
	}

	switch status.Configuration {
	case ConfigUnavailable:
		return SeverityUnavailable, []string{"code scanning configuration could not be read for this repository"}
	case ConfigNotConfigured:
		// A repository with no analyzable code is not a rollout gap.
		if status.Coverage == CoverageNoSupportedLanguages {
			return SeverityNotApplicable, []string{"no CodeQL-supported languages detected"}
		}
		if status.Execution == ExecNotEvaluated {
			return SeverityUnknown, []string{
				"default setup is disabled; advanced setup was not evaluated at this scan depth",
			}
		}
		return SeverityNotConfigured, []string{"code scanning default setup is not enabled"}
	case ConfigExternalCI:
		return SeverityUnknown, []string{
			"CodeQL analyses from external CI were detected, but external CI health is not evaluated",
		}
	case ConfigAttachFailed:
		return SeverityStalled, []string{"security configuration failed to attach"}
	case ConfigAttaching, ConfigUpdating:
		return SeverityInProgress, []string{"security configuration is still being applied"}
	case ConfigUnknown:
		return SeverityUnknown, []string{"configuration state could not be determined"}
	}

	if ExecutionStalled(status.Execution) {
		// A repository with nothing CodeQL can analyze is not a broken
		// rollout. Default setup stays "configured" on an empty repository,
		// and reporting those as stalled would bury the real failures.
		if status.Coverage == CoverageNoSupportedLanguages {
			return SeverityNotApplicable, []string{
				setupNoun(status) + " is configured but no CodeQL-supported languages were found to analyze",
			}
		}
		if status.Execution == ExecNoWorkflow {
			reasons = append(reasons, setupNoun(status)+" is configured but no CodeQL workflow exists")
		} else if status.Execution == ExecDisabled {
			reasons = append(reasons, "the CodeQL workflow is disabled and cannot run")
		} else {
			reasons = append(reasons, setupNoun(status)+" is configured but no analysis run has ever completed")
		}
		return SeverityStalled, reasons
	}

	// Execution could not be determined, so nothing downstream of it can be
	// asserted. Without this, an unreadable workflow list produces a confident
	// "never scanned" verdict out of evidence that was never obtained.
	if status.Execution == ExecUnknown {
		return SeverityUnknown, []string{"the state of the analysis run could not be determined"}
	}

	if status.Freshness == FreshNever {
		if status.Coverage == CoverageNoSupportedLanguages {
			return SeverityNotApplicable, []string{
				setupNoun(status) + " is configured but no CodeQL-supported languages were found to analyze",
			}
		}
		return SeverityStalled, []string{"no successful analysis evidence found"}
	}

	if status.Freshness == FreshStale {
		reasons = append(reasons, staleReason(status))
		return SeverityStale, reasons
	}

	if status.Coverage == CoveragePartial {
		reasons = append(reasons, "one or more configured languages are not being analyzed successfully")
	}
	if status.Coverage == CoverageGap {
		reasons = append(reasons, "supported languages in this repository are not configured for analysis")
	}
	if hasWarning {
		reasons = append(reasons, "analysis reported a warning")
	}
	if len(reasons) > 0 {
		return SeverityDegraded, reasons
	}

	if ExecutionRunning(status.Execution) {
		return SeverityInProgress, []string{"an analysis run is currently executing"}
	}

	// Configuration-only depth gathers no runtime evidence, so a repository
	// can be reported as configured and gap-free but never as healthy.
	if status.Execution == ExecNotEvaluated {
		return SeverityUnknown, []string{
			"only configuration was read at this scan depth, so scan health was not evaluated",
		}
	}

	if status.Execution == ExecSuccess {
		return SeverityHealthy, nil
	}

	return SeverityUnknown, []string{"analysis state could not be determined"}
}
