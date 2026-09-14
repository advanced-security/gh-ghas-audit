package collector

import (
	"strings"
	"testing"
	"time"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/ghapi"
	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
)

func TestQueuedRunStatesRemainDistinctFromExecution(t *testing.T) {
	for _, state := range []string{"queued", "waiting", "requested", "pending", "QUEUED", "in_progress"} {
		want := model.ExecQueued
		if state == "in_progress" {
			want = model.ExecInProgress
		}
		latest := &workflowRun{Status: state}
		for _, completed := range []*workflowRun{nil, {Status: "completed", Conclusion: "success"}} {
			if got := executionStatus(latest, completed); got != want {
				t.Errorf("%s with completed=%v: got %s, want %s", state, completed, got, want)
			}
		}
		failed := &workflowRun{Status: "completed", Conclusion: "failure"}
		if got := executionStatus(latest, failed); got != model.ExecFailure {
			t.Errorf("%s hid the previous failure: %s", state, got)
		}
	}
}

func TestSuccessfulRunLookupErrorsMarkEvidenceIncomplete(t *testing.T) {
	for _, status := range []int{0, 403, 429, 500} {
		client := buildClient(t, scenario{
			name:         "history",
			languages:    []string{"Go"},
			defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
			workflows:    codeqlWorkflows(),
			runs:         map[string]any{"": runList("failure", time.Hour)},
			jobs:         jobsFor(map[string]string{"go": "failure"}),
		})
		var response any = workflowRunList{}
		if status != 0 {
			response = &ghapi.StatusError{StatusCode: status, Message: "history unavailable"}
		}
		client.set("repos/"+testOrg+"/history/actions/workflows/99/runs?branch=main&exclude_pull_requests=true&per_page=1&status=success", response)
		report := collect(t, client, defaultActivityOptions())
		repo := findRepo(t, report, "history")
		if repo.Status.Incomplete != (status != 0) || report.Stats.Incomplete != (status != 0) {
			t.Errorf("HTTP %d: incomplete evidence was not propagated: repo=%+v, report=%+v", status, repo.Status, report.Stats)
		}
		if status != 0 {
			if !strings.Contains(strings.Join(repo.Errors, " "), "successful workflow runs") {
				t.Errorf("HTTP %d: missing error context: %v", status, repo.Errors)
			}
			if repo.Status.Freshness != model.FreshUnknown {
				t.Errorf("unread history became a definite freshness verdict: %s", repo.Status.Freshness)
			}
		} else if repo.Status.Freshness != model.FreshNever {
			t.Errorf("an empty successful history should be never-scanned: %s", repo.Status.Freshness)
		}
		if repo.Status.Overall != model.SeverityFailing {
			t.Errorf("history lookup hid a known failure: %s", repo.Status.Overall)
		}
	}
}

func TestPushAgeIsIndependentOfPullRequestActivity(t *testing.T) {
	now := time.Now()
	pushed, activity := now.Add(-300*day), now.Add(-2*day)
	for _, test := range []struct {
		name      string
		pushed    *time.Time
		activity  *time.Time
		threshold time.Duration
		wantAge   int
	}{
		{"fork-pr", &pushed, &activity, sixMonth, 300},
		{"no-push", nil, &activity, sixMonth, -1},
		{"inactivity-disabled", &pushed, &activity, 0, 300},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := &Collector{options: Options{InactiveAfter: test.threshold, Now: func() time.Time { return now }}}
			repo := model.Repo{PushedAt: test.pushed, LastActivityAt: test.activity}
			c.classifyActivity(&repo)
			if repo.Activity != model.ActivityActive {
				t.Errorf("recent PR should keep the repository active: %s", repo.Activity)
			}
			if test.wantAge < 0 {
				if repo.DaysSincePush != nil {
					t.Fatalf("push age fabricated from a PR: %d", *repo.DaysSincePush)
				}
			} else if repo.DaysSincePush == nil || *repo.DaysSincePush != test.wantAge {
				t.Fatalf("push age = %v, want %d", repo.DaysSincePush, test.wantAge)
			}
		})
	}
}
