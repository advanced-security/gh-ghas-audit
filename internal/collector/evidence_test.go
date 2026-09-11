package collector

import (
	"strings"
	"testing"
	"time"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/ghapi"
	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
)

// A language removed from default setup months ago still has old analyses
// inside the page this tool reads. Those must not be mistaken for the language
// having run in the latest analysis, which is what distinguishes "never
// enabled" from "enabled, failed, and silently dropped". Getting this wrong
// invents an error-severity finding out of ordinary history.
func TestOldAnalysisDoesNotFabricateADroppedLanguage(t *testing.T) {
	client := buildClient(t, scenario{
		name:      "history",
		languages: []string{"Go"},
		defaultSetup: defaultSetup{
			State:     "configured",
			Languages: []string{"go"},
		},
		workflows: codeqlWorkflows(),
		runs:      map[string]any{"": runList("success", time.Hour)},
		jobs:      jobsFor(map[string]string{"go": "success"}),
		databases: databasesFor([]string{"go"}, time.Hour),
	})
	// Python was configured a long time ago and has since been removed. Its
	// analysis is clean and old, and Python is no longer in the repository.
	old := time.Now().Add(-200 * 24 * time.Hour)
	recent := time.Now().Add(-time.Hour)
	client.set("repos/"+testOrg+"/history/code-scanning/analyses", []codeScanningAnalysis{
		{Category: "/language:go", AnalysisKey: codeqlWorkflowPath + ":analyze", CreatedAt: &recent, Results: 1},
		{Category: "/language:python", AnalysisKey: codeqlWorkflowPath + ":analyze", CreatedAt: &old, Results: 2},
	})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "history")

	if len(repo.DeselectedLanguages) != 0 {
		t.Fatalf("deselected languages = %v, want none; an old analysis is history, not the latest run",
			repo.DeselectedLanguages)
	}
	for _, diagnostic := range repo.Diagnostics {
		if diagnostic.Code == "language-auto-deselected" {
			t.Fatalf("fabricated a dropped-language error from history: %s", diagnostic.Message)
		}
	}
	if repo.Status.Overall != model.SeverityHealthy {
		t.Fatalf("overall = %q, want healthy (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
}

// When the jobs request cannot be read, a clean analysis must not be used to
// claim success. Databases and analyses both persist from earlier runs, so
// trusting them here would report a currently broken language as fine.
func TestUnreadableJobsPreventAnalysisFromClaimingSuccess(t *testing.T) {
	analysed := time.Now().Add(-time.Hour)
	client := buildClient(t, scenario{
		name:         "jobs-unreadable-with-analyses",
		languages:    []string{"Go"},
		defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
		workflows:    codeqlWorkflows(),
		runs:         map[string]any{"": runList("success", time.Hour)},
	})
	// Jobs return a server error rather than 404, so the evidence is unread.
	client.set("repos/"+testOrg+"/jobs-unreadable-with-analyses/actions/runs/", &ghapi.StatusError{StatusCode: 500, Message: "denied"})
	client.set("repos/"+testOrg+"/jobs-unreadable-with-analyses/code-scanning/analyses", []codeScanningAnalysis{
		{Category: "/language:go", AnalysisKey: codeqlWorkflowPath + ":analyze", CreatedAt: &analysed, Results: 1},
	})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "jobs-unreadable-with-analyses")

	if containsLanguage(repo.SucceededLanguages, model.LangGo) {
		t.Fatal("a clean analysis must not claim success while job evidence is unreadable")
	}
	if repo.Status.Overall == model.SeverityHealthy {
		t.Fatalf("overall = %q, must not be healthy on unread evidence", repo.Status.Overall)
	}
	if !repo.Status.Incomplete {
		t.Error("unread job evidence must mark the repository incomplete")
	}
}

func TestCurrentJobsPreventHistoricalAnalysisFromClaimingMissingLanguageSuccess(t *testing.T) {
	recent := time.Now().Add(-time.Hour)
	old := time.Now().Add(-30 * 24 * time.Hour)
	client := buildClient(t, scenario{
		name:      "job-omitted-language",
		languages: []string{"Go", "Python"},
		defaultSetup: defaultSetup{
			State:     "configured",
			Languages: []string{"go", "python"},
		},
		workflows: codeqlWorkflows(),
		runs:      map[string]any{"": runList("success", time.Hour)},
		jobs:      jobsFor(map[string]string{"go": "success"}),
	})
	client.set("repos/"+testOrg+"/job-omitted-language/code-scanning/analyses", []codeScanningAnalysis{
		{Category: "/language:go", AnalysisKey: codeqlWorkflowPath + ":analyze", CreatedAt: &recent},
		{Category: "/language:python", AnalysisKey: codeqlWorkflowPath + ":analyze", CreatedAt: &old},
	})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "job-omitted-language")

	if containsLanguage(repo.SucceededLanguages, model.LangPython) {
		t.Fatal("historical Python analysis masked its absence from the latest run")
	}
	if !containsLanguage(repo.FailedLanguages, model.LangPython) ||
		repo.Status.Coverage != model.CoveragePartial ||
		repo.Status.Overall != model.SeverityDegraded {
		t.Fatalf("missing latest-run language was not degraded: %+v", repo)
	}
}

// A failed analyses request is not an absence of findings. Swallowing it would
// let a token without the right permission produce a clean bill of health.
func TestUnreadableAnalysesAreRecordedNotIgnored(t *testing.T) {
	client := buildClient(t, scenario{
		name:         "analyses-unreadable",
		languages:    []string{"Go"},
		defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
		workflows:    codeqlWorkflows(),
		runs:         map[string]any{"": runList("success", time.Hour)},
		jobs:         jobsFor(map[string]string{"go": "success"}),
		databases:    databasesFor([]string{"go"}, time.Hour),
	})
	client.set("repos/"+testOrg+"/analyses-unreadable/code-scanning/analyses", &ghapi.StatusError{StatusCode: 403, Message: "denied"})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "analyses-unreadable")

	if !repo.Status.Incomplete {
		t.Fatal("an unreadable analyses response must mark the repository incomplete")
	}
	if repo.Status.Overall == model.SeverityHealthy {
		t.Fatalf("overall = %q, must not be healthy when analyses could not be read", repo.Status.Overall)
	}
	var recorded bool
	for _, message := range repo.Errors {
		if strings.Contains(message, "analyses") {
			recorded = true
		}
	}
	if !recorded {
		t.Errorf("errors = %v, want one naming the analyses request", repo.Errors)
	}
}

// Turning default setup off leaves its analyses behind. Those are not evidence
// of a repository-controlled workflow, and treating them as such would replace
// a genuine rollout gap with a claim that the repository scans itself.
func TestDisabledDefaultSetupIsNotReportedAsAdvancedSetup(t *testing.T) {
	analysed := time.Now().Add(-24 * time.Hour)
	client := buildClient(t, scenario{
		name:         "recently-disabled",
		languages:    []string{"Go"},
		defaultSetup: defaultSetup{State: "not-configured"},
		workflows:    codeqlWorkflows(),
		runs:         map[string]any{"": runList("success", 24*time.Hour)},
	})
	// The analyses came from the managed default setup workflow.
	client.set("repos/"+testOrg+"/recently-disabled/code-scanning/analyses", []codeScanningAnalysis{
		{Category: "/language:go", AnalysisKey: codeqlWorkflowPath + ":analyze", CreatedAt: &analysed, Results: 1},
	})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "recently-disabled")

	if repo.Status.Configuration == model.ConfigAdvancedSetup {
		t.Fatal("analyses left by disabled default setup must not be read as advanced setup")
	}
	if repo.Status.Overall != model.SeverityNotConfigured {
		t.Fatalf("overall = %q, want not-configured; scanning is switched off", repo.Status.Overall)
	}
}

// Code quality is a different product feature that also writes analyses under
// a dynamic workflow path. It must never be mistaken for code scanning.
func TestCodeQualityWorkflowIsNotReadAsAdvancedSetup(t *testing.T) {
	analysed := time.Now().Add(-time.Hour)
	client := buildClient(t, scenario{
		name:         "code-quality",
		languages:    []string{"Go"},
		defaultSetup: defaultSetup{State: "not-configured"},
	})
	client.set("repos/"+testOrg+"/code-quality/code-scanning/analyses", []codeScanningAnalysis{
		{
			Category:    "/language:go",
			AnalysisKey: "dynamic/github-code-quality/codeql:analyze",
			CreatedAt:   &analysed,
		},
	})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "code-quality")

	if repo.Status.Configuration == model.ConfigAdvancedSetup {
		t.Fatal("a code quality workflow must not be reported as code scanning advanced setup")
	}
}

func TestNewerCodeQualityAnalysisDoesNotHideAdvancedCodeScanning(t *testing.T) {
	recent := time.Now().Add(-time.Hour)
	older := time.Now().Add(-2 * time.Hour)
	const workflow = ".github/workflows/codeql.yml"
	client := buildClient(t, scenario{
		name:         "quality-before-scanning",
		languages:    []string{"Go"},
		defaultSetup: defaultSetup{State: "not-configured"},
		workflows:    advancedWorkflows(workflow),
		runs:         map[string]any{"": runListFor(workflow, "success", time.Hour)},
		jobs:         jobsFor(map[string]string{"go": "success"}),
	})
	client.set("repos/"+testOrg+"/quality-before-scanning/code-scanning/analyses", []codeScanningAnalysis{
		{Category: "/language:go", AnalysisKey: "dynamic/github-code-quality/codeql:analyze", CreatedAt: &recent},
		{Category: "/language:go", AnalysisKey: workflow + ":analyze", CreatedAt: &older},
	})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "quality-before-scanning")

	if repo.Status.Configuration != model.ConfigAdvancedSetup ||
		repo.Execution.WorkflowPath != workflow ||
		repo.Status.Overall != model.SeverityHealthy {
		t.Fatalf("newer Code Quality record hid advanced code scanning: %+v", repo)
	}
}

func TestConfiguredDefaultSetupSelectsItsOwnAnalyses(t *testing.T) {
	recent := time.Now().Add(-time.Hour)
	older := time.Now().Add(-2 * time.Hour)
	client := buildClient(t, scenario{
		name:         "default-with-other-codeql",
		languages:    []string{"Go"},
		defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
		workflows:    codeqlWorkflows(),
		runs:         map[string]any{"": runList("success", time.Hour)},
		jobs:         jobsFor(map[string]string{"go": "success"}),
	})
	client.set("repos/"+testOrg+"/default-with-other-codeql/code-scanning/analyses", []codeScanningAnalysis{
		{Category: "/language:go", AnalysisKey: ".github/workflows/other.yml:analyze", CreatedAt: &recent, Error: "other workflow failed"},
		{Category: "/language:go", AnalysisKey: codeqlWorkflowPath + ":analyze", CreatedAt: &older},
	})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "default-with-other-codeql")

	if repo.Status.Overall != model.SeverityHealthy {
		t.Fatalf("another workflow's analysis was attributed to default setup: %+v", repo)
	}
}

// An advanced workflow whose run conclusion is success can still contain a
// failed language, and the analysis error is the only stable signal for it.
func TestAdvancedSetupLanguageErrorSurvivesASuccessfulRun(t *testing.T) {
	analysed := time.Now().Add(-time.Hour)
	client := buildClient(t, scenario{
		name:         "advanced-green-run",
		languages:    []string{"Java", "Go"},
		defaultSetup: defaultSetup{State: "not-configured"},
		workflows:    advancedWorkflows(".github/workflows/codeql.yml"),
		// The run itself is green.
		runs: map[string]any{"": runListFor(".github/workflows/codeql.yml", "success", time.Hour)},
		jobs: jobsFor(map[string]string{"java-kotlin": "success", "go": "success"}),
	})
	client.set("repos/"+testOrg+"/advanced-green-run/code-scanning/analyses", []codeScanningAnalysis{
		{
			Category:    "/language:java-kotlin",
			AnalysisKey: ".github/workflows/codeql.yml:analyze",
			CreatedAt:   &analysed,
			Error:       "unsuccessful execution, exit code: 0, description:  ",
		},
		{
			Category:    "/language:go",
			AnalysisKey: ".github/workflows/codeql.yml:analyze",
			CreatedAt:   &analysed,
			Results:     2,
		},
	})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "advanced-green-run")

	if repo.Status.Execution != model.ExecSuccess {
		t.Fatalf("execution = %q, want success; the run itself passed", repo.Status.Execution)
	}
	if !containsLanguage(repo.FailedLanguages, model.LangJavaKotlin) {
		t.Fatalf("failed languages = %v, want java-kotlin", repo.FailedLanguages)
	}
	if repo.Status.Overall != model.SeverityDegraded {
		t.Fatalf("overall = %q, want degraded (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
}

// External CI analysis keys do not name an Actions workflow. Their categories
// are free-form and can represent several applications in one repository, so
// treating a recognized language category as complete repository coverage
// would overclaim support.
func TestAnalysisOutsideActionsIsDetectedButNotEvaluated(t *testing.T) {
	analysed := time.Now().Add(-2 * time.Hour)
	client := buildClient(t, scenario{
		name:         "external-ci",
		languages:    []string{"Go"},
		defaultSetup: defaultSetup{State: "not-configured"},
	})
	client.set("repos/"+testOrg+"/external-ci/code-scanning/analyses", []codeScanningAnalysis{
		{Category: "/language:go", AnalysisKey: "jenkins-pipeline", CreatedAt: &analysed, Results: 1},
	})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "external-ci")

	if repo.Status.Configuration != model.ConfigExternalCI {
		t.Fatalf("configuration = %q, want external-ci", repo.Status.Configuration)
	}
	if repo.Status.Overall != model.SeverityUnknown || repo.Status.Incomplete {
		t.Fatalf("external CI must be explicit but not treated as failed evidence: %+v", repo.Status)
	}
	if repo.Execution.WorkflowPath != "" {
		t.Fatalf("external CI key was treated as an Actions workflow: %q", repo.Execution.WorkflowPath)
	}
	if len(repo.Diagnostics) != 1 || repo.Diagnostics[0].Code != "external-ci-not-evaluated" {
		t.Fatalf("external CI limitation is not explained: %+v", repo.Diagnostics)
	}
}

func TestFailedAnalysisOutsideActionsDoesNotInventWorkflowHealth(t *testing.T) {
	analysed := time.Now().Add(-2 * time.Hour)
	client := buildClient(t, scenario{
		name:         "external-ci-failed",
		languages:    []string{"Go"},
		defaultSetup: defaultSetup{State: "not-configured"},
	})
	client.set("repos/"+testOrg+"/external-ci-failed/code-scanning/analyses", []codeScanningAnalysis{
		{Category: "/language:go", AnalysisKey: "jenkins-pipeline", CreatedAt: &analysed, Error: "database finalization failed"},
	})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "external-ci-failed")

	if repo.Status.Configuration != model.ConfigExternalCI || repo.Status.Overall != model.SeverityUnknown {
		t.Fatalf("external analysis was misclassified as an Actions workflow: %+v", repo.Status)
	}
}
