package collector

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/ghapi"
	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
)

// A repository can carry analyses from more than one CodeQL workflow, for
// example after migrating between setups. Per-language evidence must come from
// the workflow being assessed, otherwise another workflow's freshness, success
// or error is attributed to it.
func TestPerLanguageEvidenceComesFromOneWorkflow(t *testing.T) {
	recent := time.Now().Add(-time.Hour)
	older := time.Now().Add(-30 * 24 * time.Hour)
	client := buildClient(t, scenario{
		name:         "two-workflows",
		languages:    []string{"Java", "Go"},
		defaultSetup: defaultSetup{State: "not-configured"},
		workflows:    advancedWorkflows(".github/workflows/codeql.yml"),
		runs:         map[string]any{"": runListFor(".github/workflows/codeql.yml", "success", time.Hour)},
		jobs:         jobsFor(map[string]string{"java-kotlin": "success"}),
	})
	client.set("repos/"+testOrg+"/two-workflows/code-scanning/analyses", []codeScanningAnalysis{
		// The current workflow analyzes Java only.
		{
			Category:    "/language:java-kotlin",
			AnalysisKey: ".github/workflows/codeql.yml:analyze",
			CreatedAt:   &recent,
			Results:     3,
		},
		// A retired workflow analyzed Go long ago. It must not contribute.
		{
			Category:    "/language:go",
			AnalysisKey: ".github/workflows/old-codeql.yml:analyze",
			CreatedAt:   &older,
			Results:     9,
		},
	})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "two-workflows")

	if containsLanguage(repo.ConfiguredLanguages, model.LangGo) {
		t.Fatalf("configured languages = %v; go came from a different workflow and must not count",
			repo.ConfiguredLanguages)
	}
	if !containsLanguage(repo.MissingLanguages, model.LangGo) {
		t.Fatalf("missing languages = %v, want go; it is present but not analyzed by this workflow",
			repo.MissingLanguages)
	}
	if repo.Status.Overall != model.SeverityDegraded {
		t.Fatalf("overall = %q, want degraded (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
}

// A forbidden workflows response can mean Actions is disabled or that the
// token cannot read it. Treating it as absence produces a confident "never
// scanned" verdict from evidence that was never obtained.
func TestForbiddenWorkflowsIsNotReportedAsNoWorkflow(t *testing.T) {
	client := buildClient(t, scenario{
		name:         "actions-forbidden",
		languages:    []string{"Go"},
		defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
	})
	client.set("repos/"+testOrg+"/actions-forbidden/actions/workflows",
		&ghapi.StatusError{StatusCode: 403, Message: "Resource not accessible by integration"})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "actions-forbidden")

	if repo.Status.Execution == model.ExecNoWorkflow {
		t.Fatal("an unreadable workflow list must not be reported as no workflow existing")
	}
	if repo.Status.Overall == model.SeverityStalled {
		t.Fatalf("overall = %q; a permission problem must not become a stalled verdict", repo.Status.Overall)
	}
	if !repo.Status.Incomplete {
		t.Error("unread workflow evidence must mark the repository incomplete")
	}
}

// A genuinely absent Actions setup is still a real answer.
func TestMissingWorkflowsEndpointIsStillAbsence(t *testing.T) {
	client := buildClient(t, scenario{
		name:         "actions-absent",
		languages:    []string{"Go"},
		defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
	})
	// No workflows registered, so the fake returns 404.

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "actions-absent")

	if repo.Status.Execution != model.ExecNoWorkflow {
		t.Fatalf("execution = %q, want no-workflow", repo.Status.Execution)
	}
	if repo.Status.Overall != model.SeverityStalled {
		t.Fatalf("overall = %q, want stalled", repo.Status.Overall)
	}
}

// The single repository path must judge inactivity the same way as
// organization enumeration, otherwise the answer depends on which code path
// fetched the repository.
func TestSingleRepositoryScopeCountsPullRequestActivity(t *testing.T) {
	pushed := time.Now().Add(-300 * 24 * time.Hour)
	pullUpdated := time.Now().Add(-2 * 24 * time.Hour)

	client := newFakeClient()
	client.set("repos/"+testOrg+"/lively/languages", map[string]int{"Go": 100})
	client.set("repos/"+testOrg+"/lively/pulls", []map[string]any{
		{"updated_at": pullUpdated.Format(time.RFC3339)},
	})
	client.set("repos/"+testOrg+"/lively", map[string]any{
		"name": "lively", "html_url": "https://github.com/" + testOrg + "/lively",
		"visibility": "private", "default_branch": "main",
		"pushed_at": pushed.Format(time.RFC3339),
	})
	client.set("repos/"+testOrg+"/lively/code-scanning/default-setup",
		defaultSetup{State: "configured", Languages: []string{"go"}})
	client.set("repos/"+testOrg+"/lively/actions/workflows", codeqlWorkflows())
	client.set("repos/"+testOrg+"/lively/actions/workflows/99/runs?", runList("success", 20*24*time.Hour))
	client.set("repos/"+testOrg+"/lively/actions/runs/", jobsFor(map[string]string{"go": "success"}))

	options := defaultActivityOptions()
	options.Repository = testOrg + "/lively"
	options.Organizations = nil

	report, err := New(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	repo := findRepo(t, report, "lively")

	if repo.Activity != model.ActivityActive {
		t.Fatalf("activity = %q, want active; a pull request two days ago is activity", repo.Activity)
	}
	// Active means the weekly threshold, so a 20 day old scan is stale.
	if repo.Status.Overall != model.SeverityStale {
		t.Fatalf("overall = %q, want stale (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
}

// A truncated language list that could not be completed must not be presented
// as the full picture, because a missed language means coverage is reported
// complete over a real gap.
func TestUnrecoverableLanguageTruncationIsRecorded(t *testing.T) {
	client := buildClient(t, scenario{
		name:             "truncated",
		languages:        []string{"Go"},
		languagesHasNext: true,
		defaultSetup:     defaultSetup{State: "configured", Languages: []string{"go"}},
		workflows:        codeqlWorkflows(),
		runs:             map[string]any{"": runList("success", time.Hour)},
		jobs:             jobsFor(map[string]string{"go": "success"}),
		databases:        databasesFor([]string{"go"}, time.Hour),
	})
	// The REST fallback fails, so the truncated list is all there is.
	client.set("repos/"+testOrg+"/truncated/languages",
		&ghapi.StatusError{StatusCode: 403, Message: "denied"})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "truncated")

	if !repo.Status.Incomplete {
		t.Fatal("an incomplete language list must mark the repository incomplete")
	}
	if repo.Status.Overall == model.SeverityHealthy {
		t.Fatalf("overall = %q, must not be healthy when the language list is known to be partial",
			repo.Status.Overall)
	}
	var recorded bool
	for _, message := range repo.Errors {
		if strings.Contains(message, "languages") {
			recorded = true
		}
	}
	if !recorded {
		t.Errorf("errors = %v, want one naming the truncated language list", repo.Errors)
	}
}
