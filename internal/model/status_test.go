package model

import "testing"

func TestClassifyPrecedence(t *testing.T) {
	tests := []struct {
		name       string
		status     Status
		hasWarning bool
		want       Severity
	}{
		{
			name: "healthy when configured, successful, current and complete",
			status: Status{
				Configuration: ConfigConfigured,
				Execution:     ExecSuccess,
				Freshness:     FreshCurrent,
				Coverage:      CoverageComplete,
			},
			want: SeverityHealthy,
		},
		{
			name: "failure outranks stale and coverage problems",
			status: Status{
				Configuration: ConfigConfigured,
				Execution:     ExecFailure,
				Freshness:     FreshStale,
				Coverage:      CoveragePartial,
			},
			want: SeverityFailing,
		},
		{
			name: "failure outranks failed security configuration attachment",
			status: Status{
				Configuration: ConfigAttachFailed,
				Execution:     ExecFailure,
				Freshness:     FreshStale,
				Coverage:      CoveragePartial,
			},
			want: SeverityFailing,
		},
		{
			name: "timed out counts as failing",
			status: Status{
				Configuration: ConfigConfigured,
				Execution:     ExecTimedOut,
				Freshness:     FreshCurrent,
				Coverage:      CoverageComplete,
			},
			want: SeverityFailing,
		},
		{
			name: "configured with no workflow is stalled, not healthy",
			status: Status{
				Configuration: ConfigConfigured,
				Execution:     ExecNoWorkflow,
				Freshness:     FreshNever,
				Coverage:      CoverageGap,
			},
			want: SeverityStalled,
		},
		{
			name: "configured with no completed run is stalled",
			status: Status{
				Configuration: ConfigConfigured,
				Execution:     ExecNoCompletedRun,
				Freshness:     FreshNever,
				Coverage:      CoverageComplete,
			},
			want: SeverityStalled,
		},
		{
			name: "empty repository with nothing to analyze is not stalled",
			status: Status{
				Configuration: ConfigConfigured,
				Execution:     ExecNoWorkflow,
				Freshness:     FreshNever,
				Coverage:      CoverageNoSupportedLanguages,
			},
			want: SeverityNotApplicable,
		},
		{
			name: "stale outranks coverage problems",
			status: Status{
				Configuration: ConfigConfigured,
				Execution:     ExecSuccess,
				Freshness:     FreshStale,
				Coverage:      CoveragePartial,
			},
			want: SeverityStale,
		},
		{
			name: "successful run with an unanalyzed language is degraded",
			status: Status{
				Configuration: ConfigConfigured,
				Execution:     ExecSuccess,
				Freshness:     FreshCurrent,
				Coverage:      CoveragePartial,
			},
			want: SeverityDegraded,
		},
		{
			name: "successful run with an unconfigured language is degraded",
			status: Status{
				Configuration: ConfigConfigured,
				Execution:     ExecSuccess,
				Freshness:     FreshCurrent,
				Coverage:      CoverageGap,
			},
			want: SeverityDegraded,
		},
		{
			name: "green run with a log warning is degraded",
			status: Status{
				Configuration: ConfigConfigured,
				Execution:     ExecSuccess,
				Freshness:     FreshCurrent,
				Coverage:      CoverageComplete,
			},
			hasWarning: true,
			want:       SeverityDegraded,
		},
		{
			name: "failed configuration attachment is stalled even when set up",
			status: Status{
				Configuration: ConfigAttachFailed,
				Execution:     ExecSuccess,
				Freshness:     FreshCurrent,
				Coverage:      CoverageComplete,
			},
			want: SeverityStalled,
		},
		{
			name: "attaching configuration is in progress",
			status: Status{
				Configuration: ConfigAttaching,
				Execution:     ExecNotApplicable,
				Freshness:     FreshNotApplicable,
				Coverage:      CoverageUnknown,
			},
			want: SeverityInProgress,
		},
		{
			name: "unconfigured repository with supported code is a rollout gap",
			status: Status{
				Configuration: ConfigNotConfigured,
				Execution:     ExecNotApplicable,
				Freshness:     FreshNotApplicable,
				Coverage:      CoverageGap,
			},
			want: SeverityNotConfigured,
		},
		{
			name: "config depth cannot distinguish disabled default setup from advanced setup",
			status: Status{
				Configuration: ConfigNotConfigured,
				Execution:     ExecNotEvaluated,
				Freshness:     FreshNotEvaluated,
				Coverage:      CoverageGap,
			},
			want: SeverityUnknown,
		},
		{
			name: "external CI is detected without inventing health",
			status: Status{
				Configuration: ConfigExternalCI,
				Execution:     ExecNotApplicable,
				Freshness:     FreshUnknown,
				Coverage:      CoverageUnknown,
			},
			want: SeverityUnknown,
		},
		{
			name: "unconfigured repository with nothing to scan is not a gap",
			status: Status{
				Configuration: ConfigNotConfigured,
				Execution:     ExecNotApplicable,
				Freshness:     FreshNotApplicable,
				Coverage:      CoverageNoSupportedLanguages,
			},
			want: SeverityNotApplicable,
		},
		{
			name: "unreadable repository is reported as unavailable",
			status: Status{
				Configuration: ConfigUnavailable,
				Execution:     ExecNotApplicable,
				Freshness:     FreshNotApplicable,
				Coverage:      CoverageUnknown,
			},
			want: SeverityUnavailable,
		},
		{
			name: "running analysis is reported as in progress",
			status: Status{
				Configuration: ConfigConfigured,
				Execution:     ExecInProgress,
				Freshness:     FreshCurrent,
				Coverage:      CoverageComplete,
			},
			want: SeverityInProgress,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status := test.status
			Classify(&status, test.hasWarning)
			if status.Overall != test.want {
				t.Fatalf("got severity %q, want %q (reasons: %v)", status.Overall, test.want, status.Reasons)
			}
			if status.Overall != SeverityHealthy && len(status.Reasons) == 0 {
				t.Fatalf("severity %q should explain itself", status.Overall)
			}
		})
	}
}

func TestClassifyIsDeterministic(t *testing.T) {
	status := Status{
		Configuration: ConfigConfigured,
		Execution:     ExecSuccess,
		Freshness:     FreshCurrent,
		Coverage:      CoveragePartial,
	}

	first := status
	Classify(&first, false)
	for attempt := 0; attempt < 10; attempt++ {
		repeat := status
		Classify(&repeat, false)
		if repeat.Overall != first.Overall || len(repeat.Reasons) != len(first.Reasons) {
			t.Fatalf("classification is not deterministic: %+v vs %+v", repeat, first)
		}
	}
}

func TestNeedsAttention(t *testing.T) {
	actionable := []Severity{SeverityFailing, SeverityStalled, SeverityStale, SeverityDegraded}
	for _, severity := range actionable {
		if !NeedsAttention(severity) {
			t.Errorf("%q should need attention", severity)
		}
	}

	benign := []Severity{
		SeverityHealthy, SeverityInProgress, SeverityNotConfigured,
		SeverityNotApplicable, SeverityUnavailable, SeverityUnknown,
	}
	for _, severity := range benign {
		if NeedsAttention(severity) {
			t.Errorf("%q should not need attention", severity)
		}
	}
}

func TestSeverityRankOrdersByUrgency(t *testing.T) {
	if SeverityFailing.Rank() >= SeverityStalled.Rank() {
		t.Error("failing should sort before stalled")
	}
	if SeverityStalled.Rank() >= SeverityStale.Rank() {
		t.Error("stalled should sort before stale")
	}
	if SeverityDegraded.Rank() >= SeverityHealthy.Rank() {
		t.Error("degraded should sort before healthy")
	}
}

func TestParseSeverity(t *testing.T) {
	cases := map[string]Severity{
		"failing":         SeverityFailing,
		"NOT-CONFIGURED":  SeverityNotConfigured,
		"not_configured":  SeverityNotConfigured,
		" in-progress   ": SeverityInProgress,
	}
	for input, want := range cases {
		got, ok := ParseSeverity(input)
		if !ok || got != want {
			t.Errorf("ParseSeverity(%q) = %q, %v; want %q", input, got, ok, want)
		}
	}

	if _, ok := ParseSeverity("broken"); ok {
		t.Error("unknown severity names must be rejected so typos are not silently ignored")
	}
}
