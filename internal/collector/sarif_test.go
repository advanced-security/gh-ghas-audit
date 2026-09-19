package collector

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
	"github.com/advanced-security/gh-ghas-audit/v2/internal/sarif"
)

// fakeSarifFetcher lets tests control what a SARIF pass finds without any
// network access, and counts how many times it was asked to inspect a
// repository so gating (--deep-scope, --no-sarif) can be verified.
type fakeSarifFetcher struct {
	results map[model.Language]*sarif.Result
	err     error
	calls   int
	// lastAnalyses records what the collector asked to inspect, so a test
	// can assert an already-errored analysis was never requested.
	lastAnalyses []sarif.Analysis
}

func (f *fakeSarifFetcher) Inspect(
	_ context.Context, _, _ string, analyses []sarif.Analysis,
) (map[model.Language]*sarif.Result, error) {
	f.calls++
	f.lastAnalyses = analyses
	return f.results, f.err
}

func goScenario(name string) scenario {
	return scenario{
		name: name, languages: []string{"Go"},
		defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
		workflows:    codeqlWorkflows(), runs: map[string]any{"": runList("success", time.Hour)},
		jobs:      jobsFor(map[string]string{"go": "success"}),
		databases: databasesFor([]string{"go"}, time.Hour),
	}
}

// SARIF is an independent, opt-in evidence source. Without a SarifFetcher
// configured (--no-sarif, or a depth below diagnostics), a repository's
// language state must not be touched, so a plain diagnostics run does not
// change behavior for users who never asked for SARIF.
func TestSarifDiagnosticsDoNothingWithoutAFetcher(t *testing.T) {
	client := buildClient(t, goScenario("no-sarif"))
	client.set("repos/"+testOrg+"/no-sarif/code-scanning/analyses", analysesFor([]codeScanningAnalysis{
		{Category: "/language:go", Results: 3, AnalysisID: 555},
	}, time.Hour))

	options := defaultActivityOptions()
	options.Depth = DepthDiagnostics
	options.DeepDiagnostics = DeepDiagnosticsAll

	repo := findRepo(t, collect(t, client, options), "no-sarif")
	for _, state := range repo.Languages {
		if state.SARIFCollected || state.SARIFError != "" {
			t.Fatalf("SARIF fields were populated without a fetcher: %+v", state)
		}
	}
}

// The structural evidence a Fetcher returns (query packs, rule count, results
// by level, artifact count, inferred language) must reach the report, and a
// SARIF-inferred language that disagrees with the analysis category must be
// flagged without being treated as a failure.
func TestSarifDiagnosticsPopulateLanguageStateAndFlagMismatch(t *testing.T) {
	client := buildClient(t, goScenario("sarif-ok"))
	client.set("repos/"+testOrg+"/sarif-ok/code-scanning/analyses", analysesFor([]codeScanningAnalysis{
		{Category: "/language:go", Results: 3, AnalysisID: 555},
	}, time.Hour))

	fetcher := &fakeSarifFetcher{results: map[model.Language]*sarif.Result{
		model.LangGo: {
			// A custom or API-based upload could mislabel its category; the
			// tool evidence here intentionally disagrees with it.
			Language:       model.LangPython,
			CodeQLVersion:  "2.20.3",
			QueryPacks:     []string{"codeql/python-queries@1.0.0"},
			RuleCount:      42,
			ResultsByLevel: map[string]int{"warning": 3},
			ArtifactCount:  10,
		},
	}}

	options := defaultActivityOptions()
	options.Depth = DepthDiagnostics
	options.DeepDiagnostics = DeepDiagnosticsAll
	options.SarifFetcher = fetcher

	repo := findRepo(t, collect(t, client, options), "sarif-ok")
	if fetcher.calls != 1 {
		t.Fatalf("SarifFetcher was called %d times, want 1", fetcher.calls)
	}

	var state *model.LanguageState
	for index := range repo.Languages {
		if repo.Languages[index].Language == model.LangGo {
			state = &repo.Languages[index]
		}
	}
	if state == nil {
		t.Fatal("go language state missing from the report")
	}
	if !state.SARIFCollected {
		t.Fatal("SARIFCollected must be true once a result is applied")
	}
	if state.CodeQLVersion != "2.20.3" {
		t.Errorf("CodeQLVersion = %q, want 2.20.3", state.CodeQLVersion)
	}
	if len(state.QueryPacks) != 1 || state.QueryPacks[0] != "codeql/python-queries@1.0.0" {
		t.Errorf("QueryPacks = %v", state.QueryPacks)
	}
	if state.RuleCount == nil || *state.RuleCount != 42 {
		t.Errorf("RuleCount = %v, want 42", state.RuleCount)
	}
	if state.ArtifactCount == nil || *state.ArtifactCount != 10 {
		t.Errorf("ArtifactCount = %v, want 10", state.ArtifactCount)
	}
	if state.SARIFLanguage != model.LangPython {
		t.Errorf("SARIFLanguage = %q, want python", state.SARIFLanguage)
	}
	if !state.SARIFLanguageMismatch {
		t.Error("a category/SARIF language disagreement must be flagged")
	}
	// A mismatch is informational: it must not, by itself, degrade the
	// repository the way a genuine collection failure does.
	if repo.Status.Overall != model.SeverityHealthy {
		t.Errorf("overall = %q, a SARIF language mismatch must not change verdict", repo.Status.Overall)
	}
}

// When the fetcher fails partway through, whatever was already collected must
// be kept, the repository must be marked incomplete rather than silently
// healthy, and languages that were never collected must record why.
func TestSarifDiagnosticsFailureKeepsPartialResultsAndMarksIncomplete(t *testing.T) {
	client := buildClient(t, scenario{
		name:      "sarif-partial",
		languages: []string{"Go", "Python"},
		defaultSetup: defaultSetup{
			State: "configured", Languages: []string{"go", "python"},
		},
		workflows: codeqlWorkflows(), runs: map[string]any{"": runList("success", time.Hour)},
		jobs:      jobsFor(map[string]string{"go": "success", "python": "success"}),
		databases: databasesFor([]string{"go", "python"}, time.Hour),
	})
	client.set("repos/"+testOrg+"/sarif-partial/code-scanning/analyses", analysesFor([]codeScanningAnalysis{
		{Category: "/language:go", Results: 3, AnalysisID: 1},
		{Category: "/language:python", Results: 5, AnalysisID: 2},
	}, time.Hour))

	fetcher := &fakeSarifFetcher{
		results: map[model.Language]*sarif.Result{
			model.LangGo: {CodeQLVersion: "2.20.3", ResultsByLevel: map[string]int{}},
		},
		err: sarif.ErrBudgetExhausted,
	}

	options := defaultActivityOptions()
	options.Depth = DepthDiagnostics
	options.DeepDiagnostics = DeepDiagnosticsAll
	options.SarifFetcher = fetcher

	report := collect(t, client, options)
	repo := findRepo(t, report, "sarif-partial")

	if !repo.Status.Incomplete || !report.Stats.Incomplete {
		t.Fatalf("a partial SARIF failure must mark the repo and report incomplete: %+v", repo.Status)
	}
	if len(repo.Errors) == 0 || !strings.Contains(strings.Join(repo.Errors, " "), "sarif") {
		t.Fatalf("the SARIF failure must be recorded on the repository: %+v", repo.Errors)
	}

	var goState, pythonState *model.LanguageState
	for index := range repo.Languages {
		switch repo.Languages[index].Language {
		case model.LangGo:
			goState = &repo.Languages[index]
		case model.LangPython:
			pythonState = &repo.Languages[index]
		}
	}
	if goState == nil || !goState.SARIFCollected {
		t.Fatalf("the language collected before the budget ran out must be kept: %+v", goState)
	}
	if pythonState == nil || pythonState.SARIFCollected || pythonState.SARIFError == "" {
		t.Fatalf("the language never collected must record why, not read as clean: %+v", pythonState)
	}
}

// A custom workflow or API-based upload is not guaranteed to name its
// category "language:<name>", so its analysis would otherwise be dropped
// before SARIF collection ever sees it. Its SARIF must still be fetched
// under a placeholder key and, once the SARIF names a language that already
// has a LanguageState (from default setup or detected-language evidence),
// attached to it, with the AnalysisID set retroactively.
func TestSarifDiagnosticsAttachUnmatchedCategoryAnalysisByInferredLanguage(t *testing.T) {
	client := buildClient(t, goScenario("sarif-custom-category"))
	client.set("repos/"+testOrg+"/sarif-custom-category/code-scanning/analyses", analysesFor([]codeScanningAnalysis{
		{Category: "my-custom-scanner", Results: 3, AnalysisID: 999},
	}, time.Hour))

	fetcher := &fakeSarifFetcher{results: map[model.Language]*sarif.Result{
		model.Language("_pending-sarif:999"): {
			Language:       model.LangGo,
			CodeQLVersion:  "2.20.3",
			ResultsByLevel: map[string]int{"warning": 3},
		},
	}}

	options := defaultActivityOptions()
	options.Depth = DepthDiagnostics
	options.DeepDiagnostics = DeepDiagnosticsAll
	options.SarifFetcher = fetcher

	repo := findRepo(t, collect(t, client, options), "sarif-custom-category")

	var state *model.LanguageState
	for index := range repo.Languages {
		if repo.Languages[index].Language == model.LangGo {
			state = &repo.Languages[index]
		}
	}
	if state == nil {
		t.Fatal("go language state missing from the report")
	}
	if state.AnalysisID != 999 {
		t.Errorf("AnalysisID = %d, want 999 set retroactively from the unmatched-category analysis", state.AnalysisID)
	}
	if !state.SARIFCollected {
		t.Fatal("SARIFCollected must be true once the unmatched-category SARIF is attached")
	}
	if state.CodeQLVersion != "2.20.3" {
		t.Errorf("CodeQLVersion = %q, want 2.20.3", state.CodeQLVersion)
	}
	if repo.PendingSARIFAnalyses != nil {
		t.Errorf("PendingSARIFAnalyses must be cleared after use, got %+v", repo.PendingSARIFAnalyses)
	}
}

// When an unmatched-category analysis's SARIF names a language with no
// existing LanguageState, it must be safely skipped rather than fabricating a
// new row, which would desynchronize the already-finalized coverage counts.
func TestSarifDiagnosticsSkipsUnmatchedCategoryForAnUndetectedLanguage(t *testing.T) {
	client := buildClient(t, goScenario("sarif-custom-orphan"))
	client.set("repos/"+testOrg+"/sarif-custom-orphan/code-scanning/analyses", analysesFor([]codeScanningAnalysis{
		{Category: "my-custom-scanner", Results: 3, AnalysisID: 999},
	}, time.Hour))

	fetcher := &fakeSarifFetcher{results: map[model.Language]*sarif.Result{
		model.Language("_pending-sarif:999"): {
			Language:      model.LangRust,
			CodeQLVersion: "2.20.3",
		},
	}}

	options := defaultActivityOptions()
	options.Depth = DepthDiagnostics
	options.DeepDiagnostics = DeepDiagnosticsAll
	options.SarifFetcher = fetcher

	report := collect(t, client, options)
	repo := findRepo(t, report, "sarif-custom-orphan")

	for _, state := range repo.Languages {
		if state.Language == model.LangRust {
			t.Fatalf("no LanguageState must be fabricated for an undetected language: %+v", state)
		}
	}
}

// A CodeQL analysis GitHub already recorded an error against (for example a
// failed extraction) never produced results, so requesting its SARIF always
// fails with HTTP 422. That analysis must never be requested at all, both to
// avoid a guaranteed-failing request and to avoid a redundant error marking
// the whole report incomplete for a failure already fully explained by
// AnalysisError.
func TestSarifDiagnosticsSkipsAnalysesWithAKnownAnalysisError(t *testing.T) {
	client := buildClient(t, scenario{
		name:      "sarif-known-error",
		languages: []string{"Java", "C++"},
		defaultSetup: defaultSetup{
			State: "configured", Languages: []string{"java-kotlin", "c-cpp"},
		},
		workflows: codeqlWorkflows(), runs: map[string]any{"": runList("success", time.Hour)},
		jobs:      jobsFor(map[string]string{"java-kotlin": "success", "c-cpp": "success"}),
		databases: databasesFor([]string{"java", "c-cpp"}, time.Hour),
	})
	client.set("repos/"+testOrg+"/sarif-known-error/code-scanning/analyses", analysesFor([]codeScanningAnalysis{
		{Category: "/language:java-kotlin", Error: "unsuccessful execution, exit code: 0, description:  ", AnalysisID: 42},
		{Category: "/language:c-cpp", Results: 12, AnalysisID: 43},
	}, time.Hour))

	fetcher := &fakeSarifFetcher{results: map[model.Language]*sarif.Result{
		model.LangCCpp: {CodeQLVersion: "2.20.3", ResultsByLevel: map[string]int{}},
	}}

	options := defaultActivityOptions()
	options.Depth = DepthDiagnostics
	options.DeepDiagnostics = DeepDiagnosticsAll
	options.SarifFetcher = fetcher

	report := collect(t, client, options)
	repo := findRepo(t, report, "sarif-known-error")

	for _, analysis := range fetcher.lastAnalyses {
		if analysis.Language == model.LangJavaKotlin {
			t.Fatalf("SARIF must never be requested for an analysis with a known error: %+v", fetcher.lastAnalyses)
		}
	}
	if len(repo.Errors) != 0 || repo.Status.Incomplete || report.Stats.Incomplete {
		t.Fatalf("an already-explained analysis error must not mark the report incomplete: errors=%v incomplete=%v",
			repo.Errors, repo.Status.Incomplete)
	}

	var ccppState *model.LanguageState
	for index := range repo.Languages {
		if repo.Languages[index].Language == model.LangCCpp {
			ccppState = &repo.Languages[index]
		}
	}
	if ccppState == nil || !ccppState.SARIFCollected {
		t.Fatalf("the healthy language must still get its SARIF collected: %+v", ccppState)
	}
}

// --deep-scope problematic must apply to SARIF exactly as it does to log
// diagnostics: a healthy repository is not worth the extra download.
func TestSarifDiagnosticsRespectsProblematicScope(t *testing.T) {
	client := buildClient(t, goScenario("sarif-healthy"))
	client.set("repos/"+testOrg+"/sarif-healthy/code-scanning/analyses", analysesFor([]codeScanningAnalysis{
		{Category: "/language:go", Results: 3, AnalysisID: 555},
	}, time.Hour))

	fetcher := &fakeSarifFetcher{results: map[model.Language]*sarif.Result{}}

	options := defaultActivityOptions()
	options.Depth = DepthDiagnostics
	options.DeepDiagnostics = DeepDiagnosticsProblematic
	options.SarifFetcher = fetcher

	repo := findRepo(t, collect(t, client, options), "sarif-healthy")
	if repo.Status.Overall != model.SeverityHealthy {
		t.Fatalf("test setup must produce a healthy repo, got %q", repo.Status.Overall)
	}
	if fetcher.calls != 0 {
		t.Fatalf("a healthy repository under --deep-scope problematic must not fetch SARIF, got %d calls", fetcher.calls)
	}
}
