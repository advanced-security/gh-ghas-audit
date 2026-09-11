package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/ghapi"
	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
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

// analysisPageSize is how many recent analyses are read in one request.
// Analyses are returned newest first and a run normally produces one per
// language, so a single page covers many scan cycles for every language.
const analysisPageSize = 100

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
		// Inactivity is judged on the newer of the last push and the last
		// pull request update, so a repository kept alive by fork pull
		// requests is not given the permissive inactive threshold.
		LastActivityAt: source.LastActivityAt,
		Properties:     extra.Properties,
		// Failures recorded while enumerating carry through, so a truncated
		// language list is never presented as complete evidence.
		Errors: append([]string(nil), source.InventoryErrors...),
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

		// The default setup endpoint answers even when default setup is off,
		// and the languages it returns are then an eligibility list, not a
		// configuration: it offers javascript, javascript-typescript and
		// typescript together, which are aliases of one another. Recording any
		// of this for an unconfigured repository would invent configuration
		// that does not exist.
		//
		// This keys off setup.State rather than the classified configuration
		// status, because a repository whose security configuration failed to
		// attach still has a genuinely configured default setup.
		if strings.EqualFold(setup.State, "configured") {
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
	}
	// Missing or explicitly disabled features describe availability. Permission
	// failures and transient errors leave evidence incomplete.
	if setupErr != nil && !ghapi.IsNotFound(setupErr) && !featureUnavailable(setupErr, repo.Archived) {
		repo.Errors = append(repo.Errors, fmt.Sprintf("default setup: %v", setupErr))
	}

	// At config depth no runtime evidence is gathered at all, so no health
	// verdict is possible. Reporting configuration alone and stopping is what
	// keeps the cheap tier from claiming a repository is fine.
	if c.options.Depth == DepthConfig {
		repo.Status.Execution = model.ExecNotEvaluated
		repo.Status.Freshness = model.FreshNotEvaluated
		repo.Status.Coverage = coverageForConfigOnly(&repo, detected)
		repo.Languages = languages.Sorted()
		finalizeStatus(&repo, false)
		return repo
	}

	if !model.IsScanning(repo.Status.Configuration) {
		// Default setup is off, but CodeQL may still run from a workflow the
		// repository controls. Analyses prove it, and their analysis key names
		// the workflow, which is the only way to find it: an advanced setup
		// workflow has no fixed path.
		if repo.Status.Configuration == model.ConfigNotConfigured {
			report, err := c.collectAnalyses(ctx, org, source.Name, repo.DefaultBranch, "")
			if err != nil {
				repo.Errors = append(repo.Errors, fmt.Sprintf("analyses: %v", err))
				repo.Status.Configuration = model.ConfigUnknown
			}
			// Analyses left behind by default setup after it was switched off
			// are not evidence of an advanced setup workflow. Treating them as
			// such would replace a genuine rollout gap with a claim that the
			// repository scans itself.
			if report != nil && !report.DefaultSetup && !isManagedWorkflowPath(report.SourceKey) {
				if report.WorkflowPath == "" {
					repo.Status.Configuration = model.ConfigExternalCI
					repo.Status.Execution = model.ExecNotApplicable
					repo.Status.Freshness = model.FreshUnknown
					repo.Status.Coverage = model.CoverageUnknown
					repo.Languages = languages.Sorted()
					repo.Diagnostics = append(repo.Diagnostics, model.Diagnostic{
						Source:   model.SourceAPI,
						Severity: "info",
						Code:     "external-ci-not-evaluated",
						Message:  "CodeQL analyses from external CI were detected, but external CI health is not evaluated",
					})
					finalizeStatus(&repo, false)
					return repo
				}
				repo.Status.Configuration = model.ConfigAdvancedSetup
				c.evaluateAdvancedSetup(ctx, org, source.Name, &repo, languages, evidence, report, detected)
				return repo
			}
		}

		// Nothing further is evaluated here. Coverage still distinguishes
		// "nothing to scan" from "supported code exists but is not enabled".
		repo.Status.Execution = model.ExecNotApplicable
		repo.Status.Freshness = model.FreshNotApplicable
		repo.Status.Coverage = coverageForConfigOnly(&repo, detected)
		repo.Languages = languages.Sorted()
		finalizeStatus(&repo, false)
		return repo
	}

	c.collectExecution(ctx, org, source.Name, repo.DefaultBranch, codeqlWorkflowPath, &repo, languages, evidence)
	c.collectLanguageEvidence(ctx, org, source.Name, &repo, languages, evidence)

	// Analyses carry a per-language error field, which is the only stable API
	// that explains why an individual language failed while the run as a whole
	// reported success.
	report, err := c.collectAnalyses(ctx, org, source.Name, repo.DefaultBranch, codeqlWorkflowPath)
	if err != nil {
		repo.Errors = append(repo.Errors, fmt.Sprintf("analyses: %v", err))
	}
	applyAnalyses(report, languages, !evidence.jobsFailed && !evidence.jobsFound)

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
	evaluation := model.RuntimeEvaluated
	if repo.Status.Execution == model.ExecNotEvaluated || repo.Status.Execution == model.ExecNotApplicable {
		evaluation = model.RuntimeNotEvaluated
	} else if repo.Status.Incomplete {
		evaluation = model.RuntimeIncomplete
	}
	for index := range repo.Languages {
		repo.Languages[index].RuntimeEvaluation = evaluation
	}
	model.Classify(&repo.Status, hasWarning)
}

// evidenceState tracks whether each source of evidence could actually be read
// for a repository. It exists so that missing evidence is never substituted
// with evidence that implies success.
type evidenceState struct {
	jobsFailed bool
	jobsFound  bool
}

// repoContext carries organization-level data already gathered in bulk.
type repoContext struct {
	Properties        map[string]string
	ConfigurationName string
	AttachmentStatus  string
}

func featureUnavailable(err error, archived bool) bool {
	var status *ghapi.StatusError
	if !ghapi.IsForbidden(err) || !errors.As(err, &status) {
		return false
	}
	message := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(status.Message)), ".")
	switch message {
	case "advanced security must be enabled for this repository",
		"advanced security must be enabled for this repository to use code scanning",
		"code security must be enabled for this repository",
		"code security must be enabled for this repository to use code scanning":
		return true
	case "code scanning is not enabled for this repository":
		return archived
	default:
		return false
	}
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
	"dockerfile": true, "makefile": true, "cmake": true,
	"batchfile": true, "yaml": true, "json": true,
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

// analysisSummary is the per-language view of the most recent code scanning
// analysis. It comes from a stable, documented API, which makes it the
// preferred source of failure attribution over parsing Actions logs.
type analysisSummary struct {
	CreatedAt *time.Time
	Error     string
	Results   int
}

// analysisReport is the result of reading a repository's code scanning
// analyses: the newest analysis overall, the newest one per language, and the
// workflow that produced them.
type analysisReport struct {
	Newest    *time.Time
	Languages map[model.Language]*analysisSummary
	// SourceKey groups analyses produced by the same CodeQL configuration.
	// For Actions this is a workflow path; external CI can use any stable key.
	SourceKey string
	// WorkflowPath is the workflow that produced the newest analysis, taken
	// from analysis_key. It is empty for CodeQL uploads from external CI.
	WorkflowPath string
	// DefaultSetup reports whether that workflow is the managed default setup
	// workflow rather than one the repository controls.
	DefaultSetup bool
}

// analysisCategoryPattern extracts the language from an analysis category such
// as "/language:java-kotlin". Categories are free-form for third-party tools,
// so anything that does not match this shape is ignored rather than guessed at.
var analysisCategoryPattern = regexp.MustCompile(`(?i)language:([a-z0-9_+-]+)`)

// sourceKeyFromAnalysisKey returns the configuration portion of an analysis
// key. Actions uses "<workflow path>:<job name>"; external CI keys are
// otherwise free-form.
func sourceKeyFromAnalysisKey(key string) string {
	if index := strings.LastIndex(key, ":"); index > 0 {
		return key[:index]
	}
	return key
}

func actionsWorkflowPath(sourceKey string) string {
	if sourceKey == codeqlWorkflowPath {
		return sourceKey
	}
	if strings.HasPrefix(sourceKey, ".github/workflows/") &&
		(strings.HasSuffix(sourceKey, ".yml") || strings.HasSuffix(sourceKey, ".yaml")) {
		return sourceKey
	}
	return ""
}

// isManagedWorkflowPath reports whether a workflow path belongs to a
// GitHub-managed dynamic workflow rather than one the repository controls.
// Default setup uses "dynamic/github-code-scanning/codeql", and code quality
// uses "dynamic/github-code-quality/codeql", which is a different feature.
func isManagedWorkflowPath(path string) bool {
	return strings.HasPrefix(path, "dynamic/")
}

// collectAnalyses reads the most recent CodeQL analyses on the default branch.
//
// Each analysis carries an "error" field that names the reason a language
// failed, which is otherwise only visible by downloading Actions logs. Reading
// it here means per-language failure attribution does not depend on log
// retention or on parsing free text.
//
// Analyses are returned newest first, so the first entry seen for a language
// is its current state.
func (c *Collector) collectAnalyses(
	ctx context.Context,
	org, name, branch, preferredSource string,
) (*analysisReport, error) {
	query := url.Values{}
	query.Set("tool_name", "CodeQL")
	query.Set("per_page", strconv.Itoa(analysisPageSize))
	if branch != "" {
		query.Set("ref", "refs/heads/"+branch)
	}

	path := fmt.Sprintf("repos/%s/%s/code-scanning/analyses?%s",
		url.PathEscape(org), url.PathEscape(name), query.Encode())

	var analyses []codeScanningAnalysis
	if err := c.client.GetJSON(ctx, path, &analyses); err != nil {
		// A repository that has never run code scanning returns 404, which is
		// a real answer. Anything else, including a missing permission or an
		// exhausted rate limit, means the evidence was not read and must not
		// be mistaken for an absence of findings.
		if ghapi.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(analyses) == 0 {
		return nil, nil
	}

	// Select a code-scanning source before grouping languages. Other managed
	// products, such as Code Quality, also emit CodeQL records under dynamic/
	// keys and must not hide the actual code-scanning workflow. When discovery
	// is needed, prefer an Actions workflow we can evaluate over external CI.
	var selected string
	var external string
	for index := range analyses {
		if analyses[index].CreatedAt == nil {
			continue
		}
		source := sourceKeyFromAnalysisKey(analyses[index].AnalysisKey)
		if preferredSource != "" {
			if source == preferredSource {
				selected = source
				break
			}
			continue
		}
		if isManagedWorkflowPath(source) {
			continue
		}
		if actionsWorkflowPath(source) != "" {
			selected = source
			break
		}
		if external == "" {
			external = source
		}
	}
	if selected == "" {
		selected = external
	}
	if selected == "" {
		return nil, nil
	}

	report := &analysisReport{
		Languages:    map[model.Language]*analysisSummary{},
		SourceKey:    selected,
		WorkflowPath: actionsWorkflowPath(selected),
		DefaultSetup: selected == codeqlWorkflowPath,
	}

	for index := range analyses {
		analysis := &analyses[index]
		if sourceKeyFromAnalysisKey(analysis.AnalysisKey) != report.SourceKey {
			continue
		}
		if report.Newest == nil && analysis.CreatedAt != nil {
			report.Newest = analysis.CreatedAt
		}

		match := analysisCategoryPattern.FindStringSubmatch(analysis.Category)
		if match == nil {
			continue
		}
		language, ok := model.NormalizeLanguage(match[1])
		if !ok {
			continue
		}
		// Newest first, so an existing entry is already the current one.
		if _, seen := report.Languages[language]; seen {
			continue
		}
		report.Languages[language] = &analysisSummary{
			CreatedAt: analysis.CreatedAt,
			Error:     strings.TrimSpace(analysis.Error),
			Results:   analysis.Results,
		}
	}

	return report, nil
}

// applyAnalyses records per-language analysis evidence.
//
// An analysis error is authoritative in the negative direction: GitHub itself
// recorded the language as having failed, so it overrides any inference drawn
// from a CodeQL database, which persists from earlier successful runs.
//
// A clean analysis is only used as proof of success when nothing better is
// available for that language. A job that fails before uploading results
// leaves the previous successful analysis in place, so treating it as current
// would mask a live failure.
//
// It deliberately never sets Analyzed. That field means "ran in the latest
// run" and is what distinguishes a language dropped from the configuration
// after failing from one that was never enabled. Analyses cover months of
// history, so setting it here would report a language removed long ago as
// having just been silently dropped.
func applyAnalyses(report *analysisReport, languages model.LanguageSet, trustSuccess bool) {
	if report == nil {
		return
	}
	for language, summary := range report.Languages {
		state := languages.Get(language)
		if summary.CreatedAt != nil {
			state.AnalysisCreatedAt = summary.CreatedAt
		}
		results := summary.Results
		state.ResultsCount = &results

		if summary.Error != "" {
			state.AnalysisError = summary.Error
			state.Succeeded = false
			continue
		}

		if trustSuccess && !state.Analyzed {
			state.Succeeded = true
		}
	}
}

// evaluateAdvancedSetup assesses a repository that scans from a workflow it
// controls rather than from default setup.
//
// Everything except intent is available from stable APIs. The analysis key
// names the workflow, so execution can be read from its runs; the analyses
// carry per-language errors and timestamps. What cannot be known is which
// languages the workflow was meant to cover, because that lives in the
// workflow file. Coverage is therefore judged the same way as default setup:
// a supported language present in the repository and not analyzed is not being
// scanned, whether someone left it out of a matrix or unticked a checkbox.
func (c *Collector) evaluateAdvancedSetup(
	ctx context.Context,
	org, name string,
	repo *model.Repo,
	languages model.LanguageSet,
	evidence *evidenceState,
	report *analysisReport,
	detected []model.Language,
) {
	// Languages that produced an analysis are the configured set for an
	// advanced workflow: there is no configuration endpoint to consult, and an
	// analysis is proof the workflow asked for that language.
	configured := make([]model.Language, 0, len(report.Languages))
	for language := range report.Languages {
		languages.Get(language).Configured = true
		configured = append(configured, language)
	}
	sortLanguageSlice(configured)
	repo.ConfiguredLanguages = configured

	// Run evidence is gathered before analysis evidence is trusted, matching
	// the default setup path. Applying analyses first would let a stale clean
	// analysis claim success before any job could contradict it.
	if report.WorkflowPath != "" {
		c.collectExecution(ctx, org, name, repo.DefaultBranch, report.WorkflowPath, repo, languages, evidence)
	} else {
		repo.Status.Execution = model.ExecUnknown
	}

	applyAnalyses(report, languages, !evidence.jobsFailed && !evidence.jobsFound)

	finalizeLanguages(repo, languages)
	repo.Status.Freshness = c.freshness(repo)
	repo.Status.Coverage = coverageStatus(repo, detected)
	repo.Diagnostics = append(repo.Diagnostics, apiDiagnostics(repo)...)

	finalizeStatus(repo, hasWarningDiagnostic(repo.Diagnostics))
}

// coverageForConfigOnly classifies coverage when only configuration evidence
// was gathered. Nothing is known about what actually ran, so this reports the
// rollout gap and nothing more.
func coverageForConfigOnly(repo *model.Repo, detected []model.Language) model.CoverageStatus {
	if len(repo.ConfiguredLanguages) == 0 && len(detected) == 0 {
		return model.CoverageNoSupportedLanguages
	}
	var missing []model.Language
	for _, language := range detected {
		if !containsLanguage(repo.ConfiguredLanguages, language) && model.IsDetectable(language) {
			missing = append(missing, language)
		}
	}
	repo.MissingLanguages = missing
	if len(missing) > 0 {
		return model.CoverageGap
	}
	if len(repo.ConfiguredLanguages) == 0 {
		return model.CoverageNoSupportedLanguages
	}
	return model.CoverageComplete
}

// collectExecution finds the CodeQL workflow at the given path and its most
// relevant runs on the default branch. The path is the managed default setup
// workflow for default setup, or the workflow named by an analysis key for
// advanced setup.
func (c *Collector) collectExecution(
	ctx context.Context,
	org, name, branch, workflowPath string,
	repo *model.Repo,
	languages model.LanguageSet,
	evidence *evidenceState,
) {
	workflowID, workflowState, found, err := c.findCodeQLWorkflow(ctx, org, name, workflowPath)
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
	repo.Execution.WorkflowPath = workflowPath
	repo.Execution.WorkflowState = workflowState
	if !workflowActive(workflowState) {
		repo.Status.Execution = model.ExecDisabled
	}

	runs, err := c.fetchRuns(ctx, org, name, workflowID, branch, "", runPageSize)
	if err != nil {
		repo.Errors = append(repo.Errors, fmt.Sprintf("workflow runs: %v", err))
		if repo.Status.Execution != model.ExecDisabled {
			repo.Status.Execution = model.ExecUnknown
		}
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
		if err != nil {
			repo.Errors = append(repo.Errors, fmt.Sprintf("successful workflow runs: %v", err))
		} else if len(successRuns) > 0 {
			latestSuccessful = &successRuns[0]
		}
	}

	repo.Execution.LatestRun = toRunRef(latest)
	repo.Execution.LatestCompletedRun = toRunRef(latestCompleted)
	repo.Execution.LatestSuccessfulRun = toRunRef(latestSuccessful)
	execution := executionStatus(latest, latestCompleted)
	if repo.Status.Execution != model.ExecDisabled || model.ExecutionFailed(execution) {
		repo.Status.Execution = execution
	}

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
	err := c.client.GetPaginatedJSON(ctx, path, func(page []byte) error {
		var next jobList
		if err := json.Unmarshal(page, &next); err != nil {
			return err
		}
		list.Jobs = append(list.Jobs, next.Jobs...)
		return nil
	})
	if err != nil {
		repo.Errors = append(repo.Errors, fmt.Sprintf("run jobs: %v", err))
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
		evidence.jobsFound = true
		state.Analyzed = true
		state.JobConclusion = item.Conclusion
		state.JobURL = item.HTMLURL
		// Job evidence is authoritative in both directions. A job that ran and
		// did not succeed means the language did not succeed, whatever older
		// analyses or databases suggest.
		state.Succeeded = strings.EqualFold(item.Conclusion, "success")
	}
}

// findCodeQLWorkflow locates the workflow at the given path and reports its
// state. A workflow can exist while being disabled, manually or by GitHub
// after a period of repository inactivity, in which case it no longer runs.
func (c *Collector) findCodeQLWorkflow(ctx context.Context, org, name, wantPath string) (int64, string, bool, error) {
	var found int64
	var state string
	var exists bool

	if wantPath == "" {
		return 0, "", false, nil
	}

	path := fmt.Sprintf("repos/%s/%s/actions/workflows?per_page=100", url.PathEscape(org), url.PathEscape(name))
	err := c.client.GetPaginatedJSON(ctx, path, func(page []byte) error {
		var list workflowList
		if err := json.Unmarshal(page, &list); err != nil {
			return err
		}
		for _, workflow := range list.Workflows {
			// Matched exactly. A prefix match would also catch
			// "dynamic/github-code-quality/codeql", which is a different
			// product feature and not code scanning.
			if workflow.Path == wantPath {
				found = workflow.ID
				state = workflow.State
				exists = true
			}
		}
		return nil
	})
	if err != nil {
		// A 404 means Actions is genuinely absent for this repository, which
		// is a real answer. A 403 is not: it can mean Actions is disabled, but
		// equally that the token cannot read it. Treating those alike would
		// turn a missing permission into a confident "never scanned" verdict.
		if ghapi.IsNotFound(err) {
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
	active := activeExecutionStatus(latest.Status)
	if latestCompleted == nil {
		if active != "" {
			return active
		}
		return model.ExecNoCompletedRun
	}

	switch strings.ToLower(latestCompleted.Conclusion) {
	case "success":
		if latest != latestCompleted && active != "" {
			return active
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

func activeExecutionStatus(status string) model.ExecutionStatus {
	switch strings.ToLower(status) {
	case "in_progress":
		return model.ExecInProgress
	case "queued", "waiting", "requested", "pending":
		return model.ExecQueued
	default:
		return ""
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
		if !ghapi.IsNotFound(err) && !featureUnavailable(err, repo.Archived) {
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
		if len(repo.Errors) > 0 {
			return model.FreshUnknown
		}
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

// classifyActivity records push age separately from combined push/PR activity.
func (c *Collector) classifyActivity(repo *model.Repo) {
	now := c.now()
	repo.DaysSincePush = nil
	if repo.PushedAt != nil {
		days := int(now.Sub(*repo.PushedAt).Hours() / 24)
		repo.DaysSincePush = &days
	}
	if c.options.InactiveAfter <= 0 {
		repo.Activity = model.ActivityActive
		return
	}
	// Activity means any signal that GitHub would count as the repository
	// being in use. A pull request opened from a fork updates the parent's
	// pull requests without ever pushing to it, so the newer of the two is
	// the closest public approximation of GitHub's own rule.
	activity := repo.LastActivityAt
	if activity == nil {
		activity = repo.PushedAt
	}
	if activity == nil {
		repo.Activity = model.ActivityUnknown
		return
	}

	since := now.Sub(*activity)

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
// newest CodeQL database and then to the newest clean analysis.
//
// The analysis fallback matters for repositories whose analyses do not come
// from a discoverable Actions workflow, such as a CodeQL CLI upload from
// external CI. Without it a repository analyzed today would be reported as
// never scanned.
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
		if state.DatabaseUpdatedAt != nil {
			if newest == nil || state.DatabaseUpdatedAt.After(*newest) {
				value := *state.DatabaseUpdatedAt
				newest = &value
			}
		}
		// Only a clean analysis is evidence of a successful scan.
		if state.AnalysisCreatedAt == nil || state.AnalysisError != "" {
			continue
		}
		if newest == nil || state.AnalysisCreatedAt.After(*newest) {
			value := *state.AnalysisCreatedAt
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
		message := fmt.Sprintf(
			"%s was analyzed in the latest run but is no longer selected in default setup; "+
				"it will not be scanned again until it is re-enabled", language)
		// The analysis error names the reason GitHub dropped the language,
		// which turns this from an observation into something actionable.
		if reason := languageAnalysisError(repo, language); reason != "" {
			message = fmt.Sprintf("%s (last analysis failed: %s)", message, reason)
		}
		diagnostics = append(diagnostics, model.Diagnostic{
			Source:   model.SourceAPI,
			Severity: "error",
			Code:     "language-auto-deselected",
			Language: language,
			Message:  message,
			URL:      repo.URL + "/settings/code-scanning/default-setup",
		})
	}

	// A language whose most recent analysis carries an error is failing even
	// if the workflow reported success. This comes from a documented API
	// field, so it does not depend on log retention.
	for index := range repo.Languages {
		state := &repo.Languages[index]
		if state.AnalysisError == "" || !state.Configured {
			continue
		}
		diagnostics = append(diagnostics, model.Diagnostic{
			Source:   model.SourceAPI,
			Severity: "error",
			Code:     "language-analysis-error",
			Language: state.Language,
			Message: fmt.Sprintf("the most recent %s analysis failed: %s",
				state.Language, state.AnalysisError),
			URL: runURL,
		})
	}

	// The workflow reported success while a configured language produced no
	// successful analysis.
	if repo.Status.Execution == model.ExecSuccess {
		for _, language := range repo.FailedLanguages {
			// A recorded analysis error already explains this language, with
			// the actual reason attached.
			if languageAnalysisError(repo, language) != "" {
				continue
			}
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

// sortLanguageSlice orders languages canonically so output is deterministic.
func sortLanguageSlice(languages []model.Language) {
	set := make(map[model.Language]bool, len(languages))
	for _, language := range languages {
		set[language] = true
	}
	ordered := model.SortLanguageSet(set)
	copy(languages, ordered)
}

// languageAnalysisError returns the recorded failure reason for a language, if// GitHub attached one to its most recent analysis.
func languageAnalysisError(repo *model.Repo, wanted model.Language) string {
	for index := range repo.Languages {
		if repo.Languages[index].Language == wanted {
			return repo.Languages[index].AnalysisError
		}
	}
	return ""
}
