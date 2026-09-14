package collector

import (
	"strings"
	"testing"
	"time"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
)

// analysesFor builds an analyses payload in the shape the API returns, newest
// first, with one entry per language.
func analysesFor(entries []codeScanningAnalysis, age time.Duration) []codeScanningAnalysis {
	moment := time.Now().Add(-age)
	for index := range entries {
		entries[index].CreatedAt = &moment
		if entries[index].AnalysisKey == "" {
			entries[index].AnalysisKey = codeqlWorkflowPath + ":analyze"
		}
	}
	return entries
}

// The code scanning analyses API records a per-language "error" field. It is
// the only documented, stable signal that names why one language failed while
// the run as a whole reported success, so it must be reported rather than
// requiring the caller to opt into log parsing.
func TestAnalysisErrorSurfacesAFailingLanguage(t *testing.T) {
	client := buildClient(t, scenario{
		name:      "mixed",
		languages: []string{"Java", "C++"},
		defaultSetup: defaultSetup{
			State:     "configured",
			Languages: []string{"java-kotlin", "c-cpp"},
		},
		workflows: codeqlWorkflows(),
		runs:      map[string]any{"": runList("success", time.Hour)},
		// Both jobs report success. Only the analysis knows better.
		jobs:      jobsFor(map[string]string{"java-kotlin": "success", "c-cpp": "success"}),
		databases: databasesFor([]string{"java", "c-cpp"}, time.Hour),
	})
	client.set("repos/"+testOrg+"/mixed/code-scanning/analyses", analysesFor([]codeScanningAnalysis{
		{Category: "/language:java-kotlin", Error: "unsuccessful execution, exit code: 0, description:  "},
		{Category: "/language:c-cpp", Results: 12},
	}, time.Hour))

	repo := findRepo(t, collect(t, client, Options{}), "mixed")

	if repo.Status.Execution != model.ExecSuccess {
		t.Fatalf("execution = %q, want success; the run itself passed", repo.Status.Execution)
	}
	if !containsLanguage(repo.FailedLanguages, model.LangJavaKotlin) {
		t.Fatalf("failed languages = %v, want java-kotlin", repo.FailedLanguages)
	}
	if !containsLanguage(repo.SucceededLanguages, model.LangCCpp) {
		t.Errorf("succeeded languages = %v, want c-cpp", repo.SucceededLanguages)
	}
	if repo.Status.Coverage != model.CoveragePartial {
		t.Errorf("coverage = %q, want partial", repo.Status.Coverage)
	}
	if repo.Status.Overall != model.SeverityDegraded {
		t.Fatalf("overall = %q, want degraded (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}

	// The reason must reach the operator, otherwise they still have to open
	// the logs, which is the problem this replaces.
	var found bool
	for _, diagnostic := range repo.Diagnostics {
		if diagnostic.Code != "language-analysis-error" {
			continue
		}
		found = true
		if diagnostic.Severity != "error" {
			t.Errorf("severity = %q, want error", diagnostic.Severity)
		}
		if !strings.Contains(diagnostic.Message, "unsuccessful execution") {
			t.Errorf("message %q does not carry the recorded reason", diagnostic.Message)
		}
	}
	if !found {
		t.Fatalf("expected a language-analysis-error diagnostic, got %+v", repo.Diagnostics)
	}
}

// The per-language result count is reported without being judged. Zero results
// is normal for many languages, so it is evidence rather than a verdict.
func TestAnalysisResultCountsAreRecorded(t *testing.T) {
	client := buildClient(t, scenario{
		name:         "counted",
		languages:    []string{"Go"},
		defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
		workflows:    codeqlWorkflows(),
		runs:         map[string]any{"": runList("success", time.Hour)},
		jobs:         jobsFor(map[string]string{"go": "success"}),
		databases:    databasesFor([]string{"go"}, time.Hour),
	})
	client.set("repos/"+testOrg+"/counted/code-scanning/analyses", analysesFor([]codeScanningAnalysis{
		{Category: "/language:go", Results: 7},
	}, time.Hour))

	repo := findRepo(t, collect(t, client, Options{}), "counted")

	if repo.Status.Overall != model.SeverityHealthy {
		t.Fatalf("overall = %q, want healthy (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
	for _, state := range repo.Languages {
		if state.Language != model.LangGo {
			continue
		}
		if state.ResultsCount == nil || *state.ResultsCount != 7 {
			t.Fatalf("results count = %v, want 7", state.ResultsCount)
		}
		if state.AnalysisCreatedAt == nil {
			t.Error("the analysis timestamp should be recorded as evidence")
		}
	}
}

// A job that fails before uploading results leaves the previous successful
// analysis as the newest one for that language. Treating that stale analysis
// as current would report a broken language as healthy, which is the worst
// failure mode available to this tool.
func TestStaleCleanAnalysisDoesNotMaskAFailedJob(t *testing.T) {
	client := buildClient(t, scenario{
		name:      "regressed",
		languages: []string{"Go", "Python"},
		defaultSetup: defaultSetup{
			State:     "configured",
			Languages: []string{"go", "python"},
		},
		workflows: codeqlWorkflows(),
		runs:      map[string]any{"": runList("success", time.Hour)},
		jobs:      jobsFor(map[string]string{"go": "success", "python": "failure"}),
		databases: databasesFor([]string{"go"}, time.Hour),
	})
	// Python last analyzed cleanly a month ago, before it started failing.
	client.set("repos/"+testOrg+"/regressed/code-scanning/analyses", analysesFor([]codeScanningAnalysis{
		{Category: "/language:go", Results: 1},
		{Category: "/language:python", Results: 4},
	}, 30*24*time.Hour))

	repo := findRepo(t, collect(t, client, Options{}), "regressed")

	if !containsLanguage(repo.FailedLanguages, model.LangPython) {
		t.Fatalf("failed languages = %v, want python; a stale clean analysis must not override a failed job",
			repo.FailedLanguages)
	}
	if repo.Status.Overall == model.SeverityHealthy {
		t.Fatal("a repository with a failing language must never be reported healthy")
	}
}

// GitHub drops a language from default setup when its analysis fails. The
// analysis error names why, which turns an observation into something the
// operator can act on.
func TestAnalysisErrorExplainsADeselectedLanguage(t *testing.T) {
	client := buildClient(t, scenario{
		name:      "dropped",
		languages: []string{"Java", "Go"},
		// Java is gone from the configuration but still ran in the last run.
		defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
		workflows:    codeqlWorkflows(),
		runs:         map[string]any{"": runList("success", time.Hour)},
		jobs:         jobsFor(map[string]string{"go": "success", "java-kotlin": "failure"}),
		databases:    databasesFor([]string{"go"}, time.Hour),
	})
	client.set("repos/"+testOrg+"/dropped/code-scanning/analyses", analysesFor([]codeScanningAnalysis{
		{Category: "/language:go", Results: 2},
		{Category: "/language:java-kotlin", Error: "unsuccessful execution, exit code: 0, description:  "},
	}, time.Hour))

	repo := findRepo(t, collect(t, client, Options{}), "dropped")

	if !containsLanguage(repo.DeselectedLanguages, model.LangJavaKotlin) {
		t.Fatalf("deselected languages = %v, want java-kotlin", repo.DeselectedLanguages)
	}

	var message string
	for _, diagnostic := range repo.Diagnostics {
		if diagnostic.Code == "language-auto-deselected" {
			message = diagnostic.Message
		}
		if diagnostic.Code == "language-analysis-error" {
			t.Error("a deselected language must not also be reported as a configured language failure")
		}
	}
	if message == "" {
		t.Fatalf("expected a language-auto-deselected diagnostic, got %+v", repo.Diagnostics)
	}
	if !strings.Contains(message, "unsuccessful execution") {
		t.Errorf("message %q should explain why the language was dropped", message)
	}
}

// Third-party tools and custom CodeQL categories do not follow the
// "/language:<name>" convention. Guessing a language from them would invent
// coverage that does not exist.
func TestUnrecognizedAnalysisCategoriesAreIgnored(t *testing.T) {
	client := buildClient(t, scenario{
		name:         "third-party",
		languages:    []string{"Go"},
		defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
		workflows:    codeqlWorkflows(),
		runs:         map[string]any{"": runList("success", time.Hour)},
		jobs:         jobsFor(map[string]string{"go": "success"}),
		databases:    databasesFor([]string{"go"}, time.Hour),
	})
	client.set("repos/"+testOrg+"/third-party/code-scanning/analyses", analysesFor([]codeScanningAnalysis{
		{Category: "my-custom-scanner", Results: 99},
		{Category: "/language:go", Results: 1},
	}, time.Hour))

	repo := findRepo(t, collect(t, client, Options{}), "third-party")

	for _, state := range repo.Languages {
		if state.Language == "" || state.Language == "my-custom-scanner" {
			t.Fatalf("an unrecognized category created a bogus language: %+v", state)
		}
	}
	if repo.Status.Overall != model.SeverityHealthy {
		t.Fatalf("overall = %q, want healthy (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
}
