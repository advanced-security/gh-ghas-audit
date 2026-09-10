package collector

import (
	"testing"
	"time"

	"github.com/advanced-security/gh-ghas-audit/internal/model"
)

// A repository can run CodeQL from its own workflow rather than default setup.
// The default setup API reports "not-configured" for those, so reporting that
// verbatim would call a perfectly healthy repository a rollout gap. In an
// estate that mixes default and advanced setup that is the most common false
// positive available.
func TestAdvancedSetupIsNotReportedAsARolloutGap(t *testing.T) {
	analysed := time.Now().Add(-48 * time.Hour)
	client := buildClient(t, scenario{
		name:         "advanced",
		languages:    []string{"JavaScript"},
		defaultSetup: defaultSetup{State: "not-configured"},
		// The workflow named by the analysis key, which is how an advanced
		// setup workflow is discovered.
		workflows: advancedWorkflows(".github/workflows/codeql.yml"),
		runs:      map[string]any{"": runListFor(".github/workflows/codeql.yml", "success", 48*time.Hour)},
		jobs:      jobsFor(map[string]string{"javascript-typescript": "success"}),
	})
	client.set("repos/"+testOrg+"/advanced/code-scanning/analyses", []codeScanningAnalysis{
		{
			Category:    "/language:javascript-typescript",
			AnalysisKey: ".github/workflows/codeql.yml:analyze",
			CreatedAt:   &analysed,
			Results:     3,
		},
	})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "advanced")

	if repo.Status.Configuration != model.ConfigAdvancedSetup {
		t.Fatalf("configuration = %q, want advanced-setup", repo.Status.Configuration)
	}
	if repo.Status.Overall == model.SeverityNotConfigured {
		t.Fatal("a repository scanning through advanced setup must not be reported as not configured")
	}
	// Advanced setup is now evaluated rather than shrugged at.
	if repo.Status.Overall != model.SeverityHealthy {
		t.Fatalf("overall = %q, want healthy (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
	if repo.Execution.WorkflowPath != ".github/workflows/codeql.yml" {
		t.Errorf("workflow path = %q, want the workflow named by the analysis key", repo.Execution.WorkflowPath)
	}
	if repo.LastSuccessfulScan == nil {
		t.Error("the last analysis date should be reported as evidence that scanning happens")
	}
}

// A language present in an advanced setup repository but never analyzed is not
// being scanned. Whether someone left it out of a workflow matrix or unticked a
// default setup checkbox is invisible and irrelevant: the language is not
// covered, and default setup already reports that case as degraded.
func TestAdvancedSetupMissingLanguageIsDegraded(t *testing.T) {
	analysed := time.Now().Add(-2 * time.Hour)
	client := buildClient(t, scenario{
		name:         "advanced-skip",
		languages:    []string{"Java", "C#"},
		defaultSetup: defaultSetup{State: "not-configured"},
		workflows:    advancedWorkflows(".github/workflows/codeql.yml"),
		runs:         map[string]any{"": runListFor(".github/workflows/codeql.yml", "success", 2*time.Hour)},
		jobs:         jobsFor(map[string]string{"java-kotlin": "success"}),
	})
	// Only Java is analyzed. C# is present in the repository and absent here.
	client.set("repos/"+testOrg+"/advanced-skip/code-scanning/analyses", []codeScanningAnalysis{
		{
			Category:    "/language:java-kotlin",
			AnalysisKey: ".github/workflows/codeql.yml:analyze",
			CreatedAt:   &analysed,
			Results:     4,
		},
	})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "advanced-skip")

	if repo.Status.Configuration != model.ConfigAdvancedSetup {
		t.Fatalf("configuration = %q, want advanced-setup", repo.Status.Configuration)
	}
	if !containsLanguage(repo.MissingLanguages, model.LangCSharp) {
		t.Fatalf("missing languages = %v, want csharp", repo.MissingLanguages)
	}
	if repo.Status.Overall != model.SeverityDegraded {
		t.Fatalf("overall = %q, want degraded (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
	// A missing language is "not configured", never "silently dropped":
	// advanced setup has no mechanism that removes a failed language.
	if len(repo.DeselectedLanguages) != 0 {
		t.Errorf("deselected languages = %v, want none for advanced setup", repo.DeselectedLanguages)
	}
}

// A per-language analysis error is a failure whatever the setup mechanism.
func TestAdvancedSetupLanguageErrorIsReported(t *testing.T) {
	analysed := time.Now().Add(-time.Hour)
	client := buildClient(t, scenario{
		name:         "advanced-broken",
		languages:    []string{"Kotlin"},
		defaultSetup: defaultSetup{State: "not-configured"},
		workflows:    advancedWorkflows(".github/workflows/codeql.yml"),
		runs:         map[string]any{"": runListFor(".github/workflows/codeql.yml", "failure", time.Hour)},
		jobs:         jobsFor(map[string]string{"java-kotlin": "failure"}),
	})
	client.set("repos/"+testOrg+"/advanced-broken/code-scanning/analyses", []codeScanningAnalysis{
		{
			Category:    "/language:java-kotlin",
			AnalysisKey: ".github/workflows/codeql.yml:analyze",
			CreatedAt:   &analysed,
			Error:       "unsuccessful execution, exit code: 0, description:  ",
		},
	})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "advanced-broken")

	if repo.Status.Overall != model.SeverityFailing {
		t.Fatalf("overall = %q, want failing (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
}

// A repository with no code scanning at all is still a genuine rollout gap.
func TestRepositoryWithNoScanningIsStillReportedNotConfigured(t *testing.T) {
	client := buildClient(t, scenario{
		name:         "genuinely-off",
		languages:    []string{"Go"},
		defaultSetup: defaultSetup{State: "not-configured"},
	})
	// No analyses are registered, so the lookup finds nothing.

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "genuinely-off")

	if repo.Status.Configuration != model.ConfigNotConfigured {
		t.Fatalf("configuration = %q, want not-configured", repo.Status.Configuration)
	}
	if repo.Status.Overall != model.SeverityNotConfigured {
		t.Fatalf("overall = %q, want not-configured", repo.Status.Overall)
	}
}

// A repository with nothing CodeQL can analyze stays out of the way whether or
// not advanced setup is present.
func TestEmptyRepositoryIsNotClassifiedAsAdvancedSetup(t *testing.T) {
	client := buildClient(t, scenario{
		name:         "empty-off",
		languages:    nil,
		defaultSetup: defaultSetup{State: "not-configured"},
	})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "empty-off")

	if repo.Status.Overall != model.SeverityNotApplicable {
		t.Fatalf("overall = %q, want not-applicable", repo.Status.Overall)
	}
}
