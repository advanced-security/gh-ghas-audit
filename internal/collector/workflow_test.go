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

		// A repository whose scans have stopped must not be reported healthy,
		// even while its last run is recent and successful.
		if repo.Status.Overall == model.SeverityHealthy {
			t.Errorf("%s: overall = healthy, but scheduled scans are not running", state)
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
