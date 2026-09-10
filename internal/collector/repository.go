package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/advanced-security/gh-ghas-audit/internal/ghapi"
	"github.com/advanced-security/gh-ghas-audit/internal/model"
)

// codeqlWorkflowPath is the path GitHub assigns to the managed CodeQL workflow
// created by code scanning default setup. Matching on this exact path is what
// keeps the tool from confusing an advanced setup workflow, a third-party
// scanner, or another dynamic workflow with default setup.
const codeqlWorkflowPath = "dynamic/github-code-scanning/codeql"

// runPageSize is how many recent runs are inspected in one request. A single
// page normally contains the latest, latest completed and latest successful
// run, so most repositories need only one call.
const runPageSize = 10

// jobLanguagePattern extracts the language from an analysis job name such as
// "Analyze (java-kotlin)" or "Analyze (java-kotlin, ubuntu-latest)".
var jobLanguagePattern = regexp.MustCompile(`\(([^)]*)\)`)

// collectRepository gathers every signal for a single repository and returns a
// fully classified record. Collection failures are recorded on the record
// rather than aborting the scan, so one broken repository cannot hide the
// status of the rest of the estate.
func (c *Collector) collectRepository(ctx context.Context, org string, source apiRepository, extra repoContext) model.Repo {
	repo := model.Repo{
		Organization:  org,
		Name:          source.Name,
		FullName:      fmt.Sprintf("%s/%s", org, source.Name),
		URL:           source.URL,
		Visibility:    strings.ToLower(source.Visibility),
		Archived:      source.IsArchived,
		Fork:          source.IsFork,
		DefaultBranch: defaultBranchOf(source),
		PushedAt:      source.PushedAt,
		Properties:    extra.Properties,
	}
	if repo.URL == "" {
		repo.URL = fmt.Sprintf("https://%s/%s/%s", c.client.Host(), org, source.Name)
	}

	languages := model.LanguageSet{}
	detected := detectedLanguages(source)
	for _, language := range detected {
		languages.Get(language).Detected = true
	}
	repo.DetectedLanguages = detected
	repo.UnsupportedLanguages = unsupportedLanguages(source)

	evidence := &evidenceState{}
	c.classifyActivity(&repo)

	repo.Configuration.SecurityConfiguration = extra.ConfigurationName
	repo.Configuration.AttachmentStatus = extra.AttachmentStatus

	setup, setupErr := c.fetchDefaultSetup(ctx, org, source.Name)
	repo.Status.Configuration = resolveConfigurationStatus(setup, setupErr, extra.AttachmentStatus)
	if setup != nil {
		repo.Configuration.DefaultSetupState = setup.State
		repo.Configuration.QuerySuite = setup.QuerySuite
		repo.Configuration.Schedule = setup.Schedule
		repo.Configuration.ThreatModel = setup.ThreatModel
		repo.Configuration.RunnerType = setup.RunnerType
		repo.Configuration.RunnerLabel = setup.RunnerLabel
		repo.Configuration.UpdatedAt = setup.UpdatedAt

		configured := model.NormalizeLanguages(setup.Languages)
		repo.ConfiguredLanguages = configured
		for _, language := range configured {
			languages.Get(language).Configured = true
		}
	}
	// A missing or forbidden response is a durable fact about the repository,
	// but anything else, including an exhausted rate limit, means the data is
	// simply unknown and must be recorded as such.
	if setupErr != nil && !ghapi.IsNotFound(setupErr) && !ghapi.IsForbidden(setupErr) {
		repo.Errors = append(repo.Errors, fmt.Sprintf("default setup: %v", setupErr))
	}

	if repo.Status.Configuration != model.ConfigConfigured && repo.Status.Configuration != model.ConfigAttachFailed {
		// Default setup is off, but CodeQL may still be running from a
		// workflow the repository controls. Checking for existing analyses
		// avoids reporting a repository that scans perfectly well as a
		// rollout gap, which would be the most common false positive in an
		// estate that mixes default and advanced setup.
		if repo.Status.Configuration == model.ConfigNotConfigured {
			if latest, found := c.latestCodeQLAnalysis(ctx, org, source.Name, repo.DefaultBranch); found {
				repo.Status.Configuration = model.ConfigAdvancedSetup
				repo.LastSuccessfulScan = latest
			}
		}

		// Nothing further is evaluated here. Coverage still distinguishes
		// "nothing to scan" from "supported code exists but is not enabled".
		repo.Status.Execution = model.ExecNotApplicable
		repo.Status.Freshness = model.FreshNotApplicable
		repo.Status.Coverage = coverageForUnconfigured(detected)
		repo.Languages = languages.Sorted()
		finalizeStatus(&repo, false)
		return repo
	}

	c.collectExecution(ctx, org, source.Name, repo.DefaultBranch, &repo, languages, evidence)
	c.collectLanguageEvidence(ctx, org, source.Name, &repo, languages, evidence)

	finalizeLanguages(&repo, languages)
	repo.Status.Freshness = c.freshness(&repo)
	repo.Status.Coverage = coverageStatus(&repo, detected)
	repo.Diagnostics = append(repo.Diagnostics, apiDiagnostics(&repo)...)

	finalizeStatus(&repo, hasWarningDiagnostic(repo.Diagnostics))
	return repo
}

// finalizeStatus classifies a repository, marking it incomplete when any
// evidence could not be collected. This is what stops a repository being
// asserted healthy on the strength of a check that never ran.
func finalizeStatus(repo *model.Repo, hasWarning bool) {
	repo.Status.Incomplete = len(repo.Errors) > 0
	repo.Status.Activity = repo.Activity
	repo.Status.StaleAfter = repo.StaleAfter
	model.Classify(&repo.Status, hasWarning)
}

// evidenceState tracks whether each source of evidence could actually be read
// for a repository. It exists so that missing evidence is never substituted
// with evidence that implies success.
type evidenceState struct {
	jobsFailed bool
}

// repoContext carries organization-level data already gathered in bulk.
type repoContext struct {
	Properties        map[string]string
	ConfigurationName string
	AttachmentStatus  string
}

func defaultBranchOf(source apiRepository) string {
	if source.DefaultBranchRef != nil {
		return source.DefaultBranchRef.Name
	}
	return ""
}

func detectedLanguages(source apiRepository) []model.Language {
	names := make([]string, 0, len(source.Languages.Nodes))
	for _, node := range source.Languages.Nodes {
		names = append(names, node.Name)
	}
	all := model.NormalizeLanguages(names)

	// Languages that cannot be observed from source, such as "actions", are
	// excluded so the report never claims a coverage gap it cannot verify.
	detectable := all[:0]
	for _, language := range all {
		if model.IsDetectable(language) {
			detectable = append(detectable, language)
		}
	}
	return detectable
}

// unsupportedLanguages lists source languages present in the repository that
// CodeQL cannot analyze. Markup, styling and build description languages are
// excluded because they are present almost everywhere and carry no signal.
func unsupportedLanguages(source apiRepository) []string {
	var result []string
	seen := map[string]bool{}
	for _, node := range source.Languages.Nodes {
		name := node.Name
		if name == "" || seen[name] {
			continue
		}
		if _, supported := model.NormalizeLanguage(name); supported {
			continue
		}
		if nonSourceLanguages[strings.ToLower(name)] {
			continue
		}
		seen[name] = true
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

// nonSourceLanguages are markup, styling, data and build description formats.
// They appear in most repositories and reporting them as uncovered would bury
// the languages that genuinely lack a scanner, such as Scala or Objective-C.
var nonSourceLanguages = map[string]bool{
	"html": true, "css": true, "scss": true, "sass": true, "less": true,
	"dockerfile": true, "makefile": true, "cmake": true, "shell": true,
	"batchfile": true, "powershell": true, "yaml": true, "json": true,
	"xml": true, "markdown": true, "text": true, "vim script": true,
	"jinja": true, "handlebars": true, "mustache": true, "smarty": true,
	"procfile": true, "editorconfig": true, "gnuplot": true, "roff": true,
	"tsql": true, "plpgsql": true, "sqlpl": true, "hcl": true, "nix": true,
	"starlark": true, "just": true, "dotenv": true, "ini": true, "toml": true,
}

func (c *Collector) fetchDefaultSetup(ctx context.Context, org, repo string) (*defaultSetup, error) {
	var setup defaultSetup
	path := fmt.Sprintf("repos/%s/%s/code-scanning/default-setup", url.PathEscape(org), url.PathEscape(repo))
	if err := c.client.GetJSON(ctx, path, &setup); err != nil {
		return nil, err
	}
	return &setup, nil
}

// resolveConfigurationStatus reconciles default setup state with security
// configuration attachment state. A failed attachment is reported even when
// default setup looks fine, because it means the intended policy is not
// actually in force.
func resolveConfigurationStatus(setup *defaultSetup, setupErr error, attachment string) model.ConfigurationStatus {
	if strings.EqualFold(attachment, "failed") {
		return model.ConfigAttachFailed
	}

	if setupErr != nil {
		// A rate limit says nothing about the repository. Reporting it as
		// "unavailable" would quietly convert a transient throttle into a
		// health verdict for potentially thousands of repositories.
		if ghapi.IsRateLimited(setupErr) {
			return model.ConfigUnknown
		}
		if ghapi.IsNotFound(setupErr) || ghapi.IsForbidden(setupErr) {
			return model.ConfigUnavailable
		}
		return model.ConfigUnknown
	}
	if setup == nil {
		return model.ConfigUnknown
	}

	if strings.EqualFold(setup.State, "configured") {
		return model.ConfigConfigured
	}

	switch strings.ToLower(attachment) {
	case "attaching":
		return model.ConfigAttaching
	case "updating":
		return model.ConfigUpdating
	}
	return model.ConfigNotConfigured
}

// latestCodeQLAnalysis reports whether CodeQL has produced any analysis on the
// default branch, and when. It is used to recognize repositories that scan
// through an advanced setup workflow rather than default setup.
func (c *Collector) latestCodeQLAnalysis(ctx context.Context, org, name, branch string) (*time.Time, bool) {
	query := url.Values{}
	query.Set("tool_name", "CodeQL")
	query.Set("per_page", "1")
	if branch != "" {
		query.Set("ref", "refs/heads/"+branch)
	}

	path := fmt.Sprintf("repos/%s/%s/code-scanning/analyses?%s",
		url.PathEscape(org), url.PathEscape(name), query.Encode())

	var analyses []codeScanningAnalysis
	if err := c.client.GetJSON(ctx, path, &analyses); err != nil {
		// A repository without code scanning returns 404 here, which simply
		// means there is no advanced setup to recognize.
		return nil, false
	}
	if len(analyses) == 0 {
		return nil, false
	}
	return analyses[0].CreatedAt, true
}

// coverageForUnconfigured classifies coverage for a repository that is not
// running default setup.
func coverageForUnconfigured(detected []model.Language) model.CoverageStatus {
	if len(detected) == 0 {
		return model.CoverageNoSupportedLanguages
	}
	return model.CoverageGap
}

// collectExecution finds the managed CodeQL workflow and its most relevant
// runs on the default branch.
func (c *Collector) collectExecution(
	ctx context.Context,
	org, name, branch string,
	repo *model.Repo,
	languages model.LanguageSet,
	evidence *evidenceState,
) {
	workflowID, workflowState, found, err := c.findCodeQLWorkflow(ctx, org, name)
	if err != nil {
		repo.Errors = append(repo.Errors, fmt.Sprintf("workflows: %v", err))
		repo.Status.Execution = model.ExecUnknown
		return
	}
	if !found {
		// Default setup reports "configured" but the managed workflow does not
		// exist, so nothing will ever scan. This is the failure mode that a
		// coverage page shows as protected.
		repo.Status.Execution = model.ExecNoWorkflow
		return
	}
	repo.Execution.WorkflowPath = codeqlWorkflowPath
	repo.Execution.WorkflowState = workflowState

	runs, err := c.fetchRuns(ctx, org, name, workflowID, branch, "", runPageSize)
	if err != nil {
		repo.Errors = append(repo.Errors, fmt.Sprintf("workflow runs: %v", err))
		repo.Status.Execution = model.ExecUnknown
		return
	}

	var latest, latestCompleted, latestSuccessful *workflowRun
	for index := range runs {
		run := &runs[index]
		if latest == nil {
			latest = run
		}
		if latestCompleted == nil && strings.EqualFold(run.Status, "completed") {
			latestCompleted = run
		}
		if latestSuccessful == nil && strings.EqualFold(run.Conclusion, "success") {
			latestSuccessful = run
		}
	}

	// Only pay for a second request when the recent page contained no success,
	// which is exactly the case where proving "it has scanned before" matters.
	if latestSuccessful == nil {
		successRuns, err := c.fetchRuns(ctx, org, name, workflowID, branch, "success", 1)
		if err == nil && len(successRuns) > 0 {
			latestSuccessful = &successRuns[0]
		}
	}

	repo.Execution.LatestRun = toRunRef(latest)
	repo.Execution.LatestCompletedRun = toRunRef(latestCompleted)
	repo.Execution.LatestSuccessfulRun = toRunRef(latestSuccessful)
	repo.Status.Execution = executionStatus(latest, latestCompleted)

	if latestCompleted != nil {
		c.collectJobs(ctx, org, name, latestCompleted.ID, repo, languages, evidence)
	}
}

// collectJobs records the per-language outcome of the latest completed run.
// This is what reveals a run whose overall conclusion is green while an
// individual language failed or was never analyzed.
func (c *Collector) collectJobs(
	ctx context.Context,
	org, name string,
	runID int64,
	repo *model.Repo,
	languages model.LanguageSet,
	evidence *evidenceState,
) {
	path := fmt.Sprintf("repos/%s/%s/actions/runs/%d/jobs?filter=latest&per_page=100",
		url.PathEscape(org), url.PathEscape(name), runID)

	var list jobList
	if err := c.client.GetJSON(ctx, path, &list); err != nil {
		if !ghapi.IsNotFound(err) {
			repo.Errors = append(repo.Errors, fmt.Sprintf("run jobs: %v", err))
		}
		// Record the failure so per-language evidence is not reconstructed
		// from CodeQL databases, which persist from earlier successful runs
		// and would make a currently broken language look analyzed.
		evidence.jobsFailed = true
		return
	}

	for _, item := range list.Jobs {
		language, ok := languageFromJobName(item.Name)
		if !ok {
			continue
		}
		state := languages.Get(language)
		state.Analyzed = true
		state.JobConclusion = item.Conclusion
		state.JobURL = item.HTMLURL
		if strings.EqualFold(item.Conclusion, "success") {
			state.Succeeded = true
		}
	}
}

// findCodeQLWorkflow locates the managed default setup workflow and reports
// its state. A workflow can exist while being disabled, manually or by GitHub
// after a period of repository inactivity, in which case it no longer runs.
func (c *Collector) findCodeQLWorkflow(ctx context.Context, org, name string) (int64, string, bool, error) {
	var found int64
	var state string
	var exists bool

	path := fmt.Sprintf("repos/%s/%s/actions/workflows?per_page=100", url.PathEscape(org), url.PathEscape(name))
	err := c.client.GetPaginatedJSON(ctx, path, func(page []byte) error {
		var list workflowList
		if err := json.Unmarshal(page, &list); err != nil {
			return err
		}
		for _, workflow := range list.Workflows {
			if workflow.Path == codeqlWorkflowPath {
				found = workflow.ID
				state = workflow.State
				exists = true
			}
		}
		return nil
	})
	if err != nil {
		if ghapi.IsNotFound(err) || ghapi.IsForbidden(err) {
			// Actions can be disabled for the repository or organization.
			return 0, "", false, nil
		}
		return 0, "", false, err
	}
	return found, state, exists, nil
}

// workflowActive reports whether a workflow state means it will still run.
// Anything else, such as being disabled manually or through inactivity, means
// scheduled scans have stopped.
func workflowActive(state string) bool {
	return state == "" || strings.EqualFold(state, "active")
}

func (c *Collector) fetchRuns(ctx context.Context, org, name string, workflowID int64, branch, status string, perPage int) ([]workflowRun, error) {
	query := url.Values{}
	query.Set("per_page", fmt.Sprintf("%d", perPage))
	query.Set("exclude_pull_requests", "true")
	if branch != "" {
		query.Set("branch", branch)
	}
	if status != "" {
		query.Set("status", status)
	}

	path := fmt.Sprintf("repos/%s/%s/actions/workflows/%d/runs?%s",
		url.PathEscape(org), url.PathEscape(name), workflowID, query.Encode())

	var list workflowRunList
	if err := c.client.GetJSON(ctx, path, &list); err != nil {
		return nil, err
	}
	return list.WorkflowRun, nil
}

// executionStatus maps Actions run state onto the report's execution
// dimension, keeping "never completed" distinct from "failed".
func executionStatus(latest, latestCompleted *workflowRun) model.ExecutionStatus {
	if latest == nil {
		return model.ExecNoCompletedRun
	}
	if latestCompleted == nil {
		if isRunning(latest.Status) {
			return model.ExecInProgress
		}
		return model.ExecNoCompletedRun
	}

	switch strings.ToLower(latestCompleted.Conclusion) {
	case "success":
		if latest != latestCompleted && isRunning(latest.Status) {
			return model.ExecInProgress
		}
		return model.ExecSuccess
	case "failure":
		return model.ExecFailure
	case "timed_out":
		return model.ExecTimedOut
	case "cancelled":
		return model.ExecCancelled
	case "action_required":
		return model.ExecActionRequired
	case "startup_failure":
		return model.ExecStartupFailure
	case "":
		return model.ExecUnknown
	default:
		return model.ExecUnknown
	}
}

func isRunning(status string) bool {
	switch strings.ToLower(status) {
	case "in_progress", "queued", "waiting", "requested", "pending":
		return true
	default:
		return false
	}
}

func toRunRef(run *workflowRun) *model.RunRef {
	if run == nil {
		return nil
	}
	started := run.RunStartedAt
	if started == nil {
		started = run.CreatedAt
	}
	return &model.RunRef{
		ID:         run.ID,
		Status:     run.Status,
		Conclusion: run.Conclusion,
		Event:      run.Event,
		HeadBranch: run.HeadBranch,
		HeadSHA:    run.HeadSHA,
		StartedAt:  started,
		UpdatedAt:  run.UpdatedAt,
		URL:        run.HTMLURL,
		Attempt:    run.RunAttempt,
	}
}

// languageFromJobName extracts a CodeQL language from an Actions job name.
func languageFromJobName(name string) (model.Language, bool) {
	match := jobLanguagePattern.FindStringSubmatch(name)
	if len(match) != 2 {
		return "", false
	}
	for _, token := range strings.Split(match[1], ",") {
		if language, ok := model.NormalizeLanguage(strings.TrimSpace(token)); ok {
			return language, true
		}
	}
	return "", false
}

// collectLanguageEvidence reads CodeQL databases, which are durable proof that
// extraction and upload succeeded for a language. They remain valid evidence
// even when the most recent run failed for an unrelated reason.
func (c *Collector) collectLanguageEvidence(
	ctx context.Context,
	org, name string,
	repo *model.Repo,
	languages model.LanguageSet,
	evidence *evidenceState,
) {
	path := fmt.Sprintf("repos/%s/%s/code-scanning/codeql/databases", url.PathEscape(org), url.PathEscape(name))

	var databases []codeqlDatabase
	if err := c.client.GetJSON(ctx, path, &databases); err != nil {
		if !ghapi.IsNotFound(err) && !ghapi.IsForbidden(err) {
			repo.Errors = append(repo.Errors, fmt.Sprintf("codeql databases: %v", err))
		}
		return
	}

	hasJobEvidence := false
	for _, state := range languages {
		if state.Analyzed {
			hasJobEvidence = true
			break
		}
	}

	for _, database := range databases {
		language, ok := model.NormalizeLanguage(database.Language)
		if !ok {
			continue
		}
		state := languages.Get(language)
		state.DatabaseUpdatedAt = database.UpdatedAt

		// When there is genuinely no job data, for example because the run has
		// aged out of retention, a database is the only remaining proof that a
		// language was analyzed successfully.
		//
		// This must not apply when the jobs request failed. Databases persist
		// from earlier successful runs, so using them then would report a
		// currently broken language as analyzed.
		if !hasJobEvidence && !evidence.jobsFailed {
			state.Analyzed = true
			state.Succeeded = true
		}
	}
}

// finalizeLanguages materializes the per-language slices used by the report.
//
// The primary signal needs no run history at all: a supported language present
// in the repository but absent from the configured languages is not being
// scanned. Job evidence only adds context about why.
func finalizeLanguages(repo *model.Repo, languages model.LanguageSet) {
	repo.Languages = languages.Sorted()

	var succeeded, failed, missing, deselected []model.Language
	for index := range repo.Languages {
		state := &repo.Languages[index]

		switch {
		case state.Configured && state.Succeeded:
			succeeded = append(succeeded, state.Language)
		case state.Configured:
			failed = append(failed, state.Language)
		}

		if state.Configured {
			continue
		}

		// Detected in the repository but not configured: the language is not
		// being scanned. This comparison alone catches the problem, without
		// needing Actions history.
		if state.Detected && model.IsDetectable(state.Language) {
			missing = append(missing, state.Language)
		}

		// If it also ran in the latest analysis, it was configured until
		// recently. GitHub clears a language from default setup when its
		// analysis fails, so this distinguishes "never enabled" from "enabled,
		// failed, and silently dropped".
		if state.Analyzed {
			state.Deselected = true
			deselected = append(deselected, state.Language)
		}
	}

	repo.SucceededLanguages = succeeded
	repo.FailedLanguages = failed
	repo.MissingLanguages = missing
	repo.DeselectedLanguages = deselected
}

// freshness determines whether successful scan evidence is recent enough,
// which is the question behind "prove a scan ran and when".
//
// The threshold depends on how often GitHub actually schedules the repository.
// Active repositories scan weekly; repositories with no pushes for six months
// or more scan every 30 days at most, so holding them to the weekly threshold
// would report them stale for most of each cycle.
func (c *Collector) freshness(repo *model.Repo) model.FreshnessStatus {
	threshold, label := c.staleThreshold(repo)
	repo.StaleAfter = label

	newest := newestSuccessfulEvidence(repo)
	if newest == nil {
		return model.FreshNever
	}

	repo.LastSuccessfulScan = newest
	age := c.now().Sub(*newest)
	days := int(age.Hours() / 24)
	repo.StaleDays = &days

	if age > threshold {
		return model.FreshStale
	}
	return model.FreshCurrent
}

// classifyActivity records how long ago the repository was last pushed to and
// whether that makes it inactive.
//
// The repository push timestamp is the closest public signal to GitHub's own
// "no pushes or pull requests" rule. Opening a pull request requires pushing a
// branch, so the two agree in practice, but this remains an approximation.
func (c *Collector) classifyActivity(repo *model.Repo) {
	if c.options.InactiveAfter <= 0 {
		repo.Activity = model.ActivityActive
		return
	}
	if repo.PushedAt == nil {
		repo.Activity = model.ActivityUnknown
		return
	}

	since := c.now().Sub(*repo.PushedAt)
	days := int(since.Hours() / 24)
	repo.DaysSincePush = &days

	if since >= c.options.InactiveAfter {
		repo.Activity = model.ActivityInactive
		return
	}
	repo.Activity = model.ActivityActive
}

// staleThreshold returns the freshness threshold for a repository and a label
// explaining which one was applied.
func (c *Collector) staleThreshold(repo *model.Repo) (time.Duration, string) {
	if repo.Activity == model.ActivityInactive && c.options.StaleAfterInactive > 0 {
		return c.options.StaleAfterInactive, formatDuration(c.options.StaleAfterInactive) + " (inactive)"
	}
	return c.options.StaleAfter, formatDuration(c.options.StaleAfter)
}

// newestSuccessfulEvidence prefers the last successful run, falling back to the
// newest CodeQL database when run history is unavailable.
func newestSuccessfulEvidence(repo *model.Repo) *time.Time {
	var newest *time.Time

	if run := repo.Execution.LatestSuccessfulRun; run != nil {
		if run.UpdatedAt != nil {
			newest = run.UpdatedAt
		} else if run.StartedAt != nil {
			newest = run.StartedAt
		}
	}

	for _, state := range repo.Languages {
		if state.DatabaseUpdatedAt == nil {
			continue
		}
		if newest == nil || state.DatabaseUpdatedAt.After(*newest) {
			value := *state.DatabaseUpdatedAt
			newest = &value
		}
	}

	return newest
}

// coverageStatus compares what should be analyzed against what actually was.
func coverageStatus(repo *model.Repo, detected []model.Language) model.CoverageStatus {
	// A language that was dropped from the configuration after failing is the
	// most serious coverage problem, because nothing will scan it again and
	// nothing else in the product surfaces it.
	if len(repo.DeselectedLanguages) > 0 {
		return model.CoveragePartial
	}
	if len(repo.ConfiguredLanguages) == 0 && len(detected) == 0 {
		return model.CoverageNoSupportedLanguages
	}
	if len(repo.FailedLanguages) > 0 {
		return model.CoveragePartial
	}
	if len(repo.MissingLanguages) > 0 {
		return model.CoverageGap
	}
	if len(repo.ConfiguredLanguages) == 0 {
		return model.CoverageNoSupportedLanguages
	}
	return model.CoverageComplete
}

// apiDiagnostics derives findings from stable API fields only. Anything more
// detailed requires log parsing and is reported separately as best effort.
func apiDiagnostics(repo *model.Repo) []model.Diagnostic {
	var diagnostics []model.Diagnostic

	runURL := ""
	if repo.Execution.LatestCompletedRun != nil {
		runURL = repo.Execution.LatestCompletedRun.URL
	}

	// The highest-value finding: a language ran, failed, and has been removed
	// from the configuration, so nothing will scan it again. No other view
	// surfaces this.
	for _, language := range repo.DeselectedLanguages {
		diagnostics = append(diagnostics, model.Diagnostic{
			Source:   model.SourceAPI,
			Severity: "error",
			Code:     "language-auto-deselected",
			Language: language,
			Message: fmt.Sprintf(
				"%s was analyzed in the latest run but is no longer selected in default setup; "+
					"it will not be scanned again until it is re-enabled", language),
			URL: repo.URL + "/settings/code-scanning/default-setup",
		})
	}

	// The workflow reported success while a configured language produced no
	// successful analysis.
	if repo.Status.Execution == model.ExecSuccess {
		for _, language := range repo.FailedLanguages {
			diagnostics = append(diagnostics, model.Diagnostic{
				Source:   model.SourceAPI,
				Severity: "warning",
				Code:     "language-not-analyzed",
				Language: language,
				Message: fmt.Sprintf(
					"the latest analysis run succeeded but %s produced no successful analysis", language),
				URL: runURL,
			})
		}
	}

	for _, language := range repo.MissingLanguages {
		// A language that was dropped after failing is reported separately
		// above, with the stronger message.
		if containsLanguage(repo.DeselectedLanguages, language) {
			continue
		}
		diagnostics = append(diagnostics, model.Diagnostic{
			Source:   model.SourceAPI,
			Severity: "warning",
			Code:     "language-not-configured",
			Language: language,
			Message: fmt.Sprintf(
				"%s was detected in this repository but is not configured for analysis", language),
			URL: repo.URL + "/settings/code-scanning/default-setup",
		})
	}

	if repo.Status.Configuration == model.ConfigAttachFailed {
		diagnostics = append(diagnostics, model.Diagnostic{
			Source:   model.SourceAPI,
			Severity: "error",
			Code:     "configuration-attach-failed",
			Message: fmt.Sprintf("security configuration %q failed to attach to this repository",
				repo.Configuration.SecurityConfiguration),
			URL: repo.URL + "/settings/security_analysis",
		})
	}

	// A workflow that exists but is disabled will not run again, whether it
	// was disabled manually or automatically after a period of inactivity.
	if state := repo.Execution.WorkflowState; !workflowActive(state) {
		diagnostics = append(diagnostics, model.Diagnostic{
			Source:   model.SourceAPI,
			Severity: "warning",
			Code:     "workflow-disabled",
			Message: fmt.Sprintf(
				"the managed CodeQL workflow exists but is %s, so scheduled scans are not running",
				strings.ReplaceAll(state, "_", " ")),
			URL: repo.URL + "/actions",
		})
	}

	return diagnostics
}

// hasWarningDiagnostic reports whether any diagnostic is severe enough to
// change a repository's verdict.
//
// Informational findings are deliberately excluded. GitHub's tool status page
// shows conditions such as private package registry use as suggestions while
// still reporting the configuration as working as expected, and this report
// must not contradict it.
func hasWarningDiagnostic(diagnostics []model.Diagnostic) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Severity == "warning" || diagnostic.Severity == "error" {
			return true
		}
	}
	return false
}

// containsLanguage reports whether a language appears in a list.
func containsLanguage(languages []model.Language, wanted model.Language) bool {
	for _, language := range languages {
		if language == wanted {
			return true
		}
	}
	return false
}
