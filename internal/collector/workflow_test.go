package collector

import (
	"testing"
	"time"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
)

// workflowWithState builds a workflow listing whose managed CodeQL entry has a
// given Actions state.
func workflowWithState(state string) workflowList {
	return workflowList{
		TotalCount: 1,
		Workflows: []struct {
			ID    int64  `json:"id"`
			Name  string `json:"name"`
			Path  string `json:"path"`
			State string `json:"state"`
		}{{ID: 99, Name: "CodeQL", Path: codeqlWorkflowPath, State: state}},
	}
}

// A workflow can exist while being disabled, in which case it no longer runs.
// GitHub disables workflows automatically after a period of repository
// inactivity, so this is reached without anyone touching the settings.
func TestDisabledWorkflowIsReported(t *testing.T) {
	for _, state := range []string{"disabled_manually", "disabled_inactivity", "disabled_fork"} {
		client := buildClient(t, scenario{
			name:         "disabled",
			languages:    []string{"Go"},
			defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
			workflows:    workflowWithState(state),
			runs:         map[string]any{"": runList("success", time.Hour)},
			jobs:         jobsFor(map[string]string{"go": "success"}),
			databases:    databasesFor([]string{"go"}, time.Hour),
		})

		repo := findRepo(t, collect(t, client, defaultActivityOptions()), "disabled")

		if repo.Execution.WorkflowState != state {
			t.Errorf("workflow state = %q, want %q", repo.Execution.WorkflowState, state)
		}

		var found bool
		for _, diagnostic := range repo.Diagnostics {
			if diagnostic.Code == "workflow-disabled" {
				found = true
				if diagnostic.Severity != "warning" {
					t.Errorf("%s: severity = %q, want warning", state, diagnostic.Severity)
				}
			}
		}
		if !found {
			t.Errorf("%s: expected a workflow-disabled diagnostic, got %+v", state, repo.Diagnostics)
		}

		if repo.Status.Execution != model.ExecutionStatus("disabled") || repo.Status.Overall != model.SeverityStalled {
			t.Errorf("%s: disabled scans must be stalled, got %+v", state, repo.Status)
		}
	}
}

// An active workflow is the normal case and must not be flagged.
func TestActiveWorkflowIsNotReported(t *testing.T) {
	client := buildClient(t, scenario{
		name:         "active",
		languages:    []string{"Go"},
		defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
		workflows:    workflowWithState("active"),
		runs:         map[string]any{"": runList("success", time.Hour)},
		jobs:         jobsFor(map[string]string{"go": "success"}),
		databases:    databasesFor([]string{"go"}, time.Hour),
	})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "active")

	for _, diagnostic := range repo.Diagnostics {
		if diagnostic.Code == "workflow-disabled" {
			t.Fatalf("an active workflow must not be flagged, got %+v", diagnostic)
		}
	}
	if repo.Status.Overall != model.SeverityHealthy {
		t.Fatalf("overall = %q, want healthy (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
}

// A workflow listing that omits the state field must not be treated as
// disabled, so missing data never invents a problem.
func TestMissingWorkflowStateIsTreatedAsActive(t *testing.T) {
	client := buildClient(t, scenario{
		name:         "no-state",
		languages:    []string{"Go"},
		defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
		workflows:    workflowWithState(""),
		runs:         map[string]any{"": runList("success", time.Hour)},
		jobs:         jobsFor(map[string]string{"go": "success"}),
		databases:    databasesFor([]string{"go"}, time.Hour),
	})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "no-state")
	if repo.Status.Overall != model.SeverityHealthy {
		t.Fatalf("overall = %q, want healthy", repo.Status.Overall)
	}
}

func TestWorkflowActive(t *testing.T) {
	for _, state := range []string{"active", "ACTIVE", ""} {
		if !workflowActive(state) {
			t.Errorf("workflowActive(%q) = false, want true", state)
		}
	}
	for _, state := range []string{"disabled_manually", "disabled_inactivity", "disabled_fork", "deleted"} {
		if workflowActive(state) {
			t.Errorf("workflowActive(%q) = true, want false", state)
		}
	}
}

func TestDisabledWorkflowPreservesKnownFailure(t *testing.T) {
	client := buildClient(t, scenario{
		name:         "disabled-failed",
		languages:    []string{"Go"},
		defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
		workflows:    workflowWithState("disabled_manually"),
		runs:         map[string]any{"": runList("failure", time.Hour)},
		jobs:         jobsFor(map[string]string{"go": "failure"}),
	})
	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "disabled-failed")
	if repo.Status.Overall != model.SeverityFailing || repo.Status.Execution != model.ExecFailure {
		t.Fatalf("disabled state hid a known failed run: %+v", repo.Status)
	}
}

func TestDisabledAdvancedWorkflowIsStalledRatherThanStale(t *testing.T) {
	const path = ".github/workflows/codeql.yml"
	workflows := advancedWorkflows(path)
	workflows.Workflows[0].State = "disabled_inactivity"
	client := buildClient(t, scenario{
		name: "disabled-advanced", languages: []string{"Go"},
		defaultSetup: defaultSetup{State: "not-configured"},
		workflows:    workflows,
		runs:         map[string]any{"": runListFor(path, "success", 20*day)},
		jobs:         jobsFor(map[string]string{"go": "success"}),
	})
	older := time.Now().Add(-20 * day)
	client.set("repos/"+testOrg+"/disabled-advanced/code-scanning/analyses", []codeScanningAnalysis{
		{AnalysisKey: path + ":analyze", Category: "/language:go", CreatedAt: &older},
	})
	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "disabled-advanced")
	if repo.Status.Execution != model.ExecDisabled || repo.Status.Overall != model.SeverityStalled {
		t.Fatalf("disabled advanced workflow is not stalled: %+v", repo.Status)
	}
	if repo.Execution.LatestCompletedRun.Conclusion != "success" {
		t.Fatal("disabled workflow lost its historical run evidence")
	}
}
