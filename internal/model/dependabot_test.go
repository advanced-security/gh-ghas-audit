package model

import "testing"

func TestClassifyDependabotPrecedence(t *testing.T) {
	tests := []struct {
		name   string
		status DependabotStatus
		want   Severity
	}{
		{
			name: "healthy when every dimension is clean",
			status: DependabotStatus{
				DependencyGraph:           FeatureEnabled,
				DependencyGraphCoverage:   GraphCoverageComplete,
				DependabotAlerts:          FeatureEnabled,
				DependabotSecurityUpdates: FeatureEnabled,
				VersionUpdates:            VersionUpdatesConfigured,
				PullRequestHealth:         PRHealthHealthy,
				DependencyReview:          DependencyReviewEnforced,
			},
			want: SeverityHealthy,
		},
		{
			name: "healthy with no open pull requests and no version updates configured is still fine",
			status: DependabotStatus{
				DependencyGraph:         FeatureEnabled,
				DependencyGraphCoverage: GraphCoverageNotApplicable,
				DependabotAlerts:        FeatureEnabled,
				VersionUpdates:          VersionUpdatesNotConfigured,
				PullRequestHealth:       PRHealthNone,
				DependencyReview:        DependencyReviewEnforced,
			},
			want: SeverityHealthy,
		},
		{
			name: "disabled dependency graph outranks everything else",
			status: DependabotStatus{
				DependencyGraph:   FeatureDisabled,
				DependabotAlerts:  FeatureEnabled,
				PullRequestHealth: PRHealthFailingChecks,
			},
			want: SeverityStalled,
		},
		{
			name: "failing pull request checks outrank backlog and coverage gaps",
			status: DependabotStatus{
				DependencyGraph:         FeatureEnabled,
				DependencyGraphCoverage: GraphCoveragePartial,
				DependabotAlerts:        FeatureEnabled,
				PullRequestHealth:       PRHealthFailingChecks,
			},
			want: SeverityFailing,
		},
		{
			name: "paused for inactivity outranks backlog",
			status: DependabotStatus{
				DependencyGraph:   FeatureEnabled,
				DependabotAlerts:  FeatureEnabled,
				VersionUpdates:    VersionUpdatesPausedInactivity,
				PullRequestHealth: PRHealthBacklogged,
			},
			want: SeverityStalled,
		},
		{
			name: "backlogged pull requests are degraded",
			status: DependabotStatus{
				DependencyGraph:   FeatureEnabled,
				DependabotAlerts:  FeatureEnabled,
				VersionUpdates:    VersionUpdatesConfigured,
				PullRequestHealth: PRHealthBacklogged,
			},
			want: SeverityDegraded,
		},
		{
			name: "missing dependency review enforcement is degraded",
			status: DependabotStatus{
				DependencyGraph:   FeatureEnabled,
				DependabotAlerts:  FeatureEnabled,
				PullRequestHealth: PRHealthHealthy,
				DependencyReview:  DependencyReviewNotEnforced,
			},
			want: SeverityDegraded,
		},
		{
			name: "manifests missing transitive dependencies with no mitigation are degraded",
			status: DependabotStatus{
				DependencyGraph:         FeatureEnabled,
				DependencyGraphCoverage: GraphCoveragePartial,
				DependabotAlerts:        FeatureEnabled,
				PullRequestHealth:       PRHealthHealthy,
				DependencyReview:        DependencyReviewEnforced,
			},
			want: SeverityDegraded,
		},
		{
			name: "auto-submission mitigation is not a gap",
			status: DependabotStatus{
				DependencyGraph:         FeatureEnabled,
				DependencyGraphCoverage: GraphCoverageMitigated,
				DependabotAlerts:        FeatureEnabled,
				PullRequestHealth:       PRHealthHealthy,
				DependencyReview:        DependencyReviewEnforced,
			},
			want: SeverityHealthy,
		},
		{
			name: "unparsable dependabot.yml is degraded",
			status: DependabotStatus{
				DependencyGraph:   FeatureEnabled,
				DependabotAlerts:  FeatureEnabled,
				VersionUpdates:    VersionUpdatesParseError,
				PullRequestHealth: PRHealthHealthy,
				DependencyReview:  DependencyReviewEnforced,
			},
			want: SeverityDegraded,
		},
		{
			name: "disabled dependabot alerts are degraded",
			status: DependabotStatus{
				DependencyGraph:   FeatureEnabled,
				DependabotAlerts:  FeatureDisabled,
				VersionUpdates:    VersionUpdatesConfigured,
				PullRequestHealth: PRHealthHealthy,
				DependencyReview:  DependencyReviewEnforced,
			},
			want: SeverityDegraded,
		},
		{
			name: "nothing configured at all is a rollout gap",
			status: DependabotStatus{
				DependencyGraph:  FeatureNotSet,
				DependabotAlerts: FeatureNotSet,
				VersionUpdates:   VersionUpdatesNotConfigured,
			},
			want: SeverityNotConfigured,
		},
		{
			name: "unreadable configuration is unknown",
			status: DependabotStatus{
				DependencyGraph:  FeatureUnknown,
				DependabotAlerts: FeatureUnknown,
			},
			want: SeverityUnknown,
		},
		{
			name: "health depth reports healthy even though dependency review is only checked at diagnostics depth",
			status: DependabotStatus{
				DependencyGraph:         FeatureEnabled,
				DependencyGraphCoverage: GraphCoverageComplete,
				DependabotAlerts:        FeatureEnabled,
				VersionUpdates:          VersionUpdatesConfigured,
				PullRequestHealth:       PRHealthHealthy,
				DependencyReview:        DependencyReviewNotEvaluated,
			},
			want: SeverityHealthy,
		},
		{
			name: "config depth never reports healthy",
			status: DependabotStatus{
				DependencyGraph:           FeatureNotEvaluated,
				DependabotSecurityUpdates: FeatureEnabled,
				VersionUpdates:            VersionUpdatesConfigured,
				PullRequestHealth:         PRHealthNotEvaluated,
				DependencyReview:          DependencyReviewNotEvaluated,
				DependencyGraphCoverage:   GraphCoverageNotEvaluated,
			},
			want: SeverityUnknown,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status := test.status
			ClassifyDependabot(&status)
			if status.Overall != test.want {
				t.Fatalf("got severity %q, want %q (reasons: %v)", status.Overall, test.want, status.Reasons)
			}
			if status.Overall != SeverityHealthy && len(status.Reasons) == 0 {
				t.Fatalf("severity %q should explain itself", status.Overall)
			}
		})
	}
}

func TestClassifyDependabotDemotesIncompleteHealthy(t *testing.T) {
	status := DependabotStatus{
		DependencyGraph:         FeatureEnabled,
		DependencyGraphCoverage: GraphCoverageComplete,
		DependabotAlerts:        FeatureEnabled,
		VersionUpdates:          VersionUpdatesConfigured,
		PullRequestHealth:       PRHealthHealthy,
		DependencyReview:        DependencyReviewEnforced,
		Incomplete:              true,
	}
	ClassifyDependabot(&status)
	if status.Overall != SeverityUnknown {
		t.Fatalf("incomplete evidence must never be reported healthy, got %q", status.Overall)
	}
	if len(status.Reasons) == 0 {
		t.Fatal("demoted severity should explain itself")
	}
}

func TestClassifyDependabotIsDeterministic(t *testing.T) {
	status := DependabotStatus{
		DependencyGraph:         FeatureEnabled,
		DependencyGraphCoverage: GraphCoveragePartial,
		DependabotAlerts:        FeatureEnabled,
		PullRequestHealth:       PRHealthBacklogged,
	}

	first := status
	ClassifyDependabot(&first)
	for attempt := 0; attempt < 10; attempt++ {
		repeat := status
		ClassifyDependabot(&repeat)
		if repeat.Overall != first.Overall || len(repeat.Reasons) != len(first.Reasons) {
			t.Fatalf("classification is not deterministic: %+v vs %+v", repeat, first)
		}
	}
}

func TestBuildDependabotSummary(t *testing.T) {
	repos := []DependabotRepo{
		{Status: DependabotStatus{Overall: SeverityHealthy}},
		{Status: DependabotStatus{Overall: SeverityFailing}},
		{Status: DependabotStatus{Overall: SeverityDegraded}},
	}
	summary := BuildDependabotSummary(repos)
	if summary.TotalRepositories != 3 {
		t.Fatalf("total repositories = %d, want 3", summary.TotalRepositories)
	}
	if summary.NeedsAttention != 2 {
		t.Fatalf("needs attention = %d, want 2", summary.NeedsAttention)
	}
	if summary.BySeverity[string(SeverityHealthy)] != 1 || summary.BySeverity[string(SeverityFailing)] != 1 {
		t.Fatalf("unexpected by-severity counts: %+v", summary.BySeverity)
	}
}

func TestBuildDependabotOrgReports(t *testing.T) {
	repos := []DependabotRepo{
		{Organization: "acme", Status: DependabotStatus{Overall: SeverityHealthy}},
		{Organization: "acme", Status: DependabotStatus{Overall: SeverityFailing}},
		{Organization: "other", Status: DependabotStatus{Overall: SeverityDegraded}},
	}
	reports := BuildDependabotOrgReports(repos)
	if len(reports) != 2 {
		t.Fatalf("org reports = %d, want 2", len(reports))
	}
	if reports[0].Login != "acme" || reports[0].TotalRepositories != 2 || reports[0].NeedsAttention != 1 {
		t.Fatalf("unexpected acme report: %+v", reports[0])
	}
	if reports[1].Login != "other" || reports[1].TotalRepositories != 1 || reports[1].NeedsAttention != 1 {
		t.Fatalf("unexpected other report: %+v", reports[1])
	}
}

func TestSortDependabotRepos(t *testing.T) {
	repos := []DependabotRepo{
		{Organization: "acme", Name: "zeta", Status: DependabotStatus{Overall: SeverityHealthy}},
		{Organization: "acme", Name: "alpha", Status: DependabotStatus{Overall: SeverityFailing}},
		{Organization: "acme", Name: "beta", Status: DependabotStatus{Overall: SeverityFailing}},
	}
	SortDependabotRepos(repos)
	if repos[0].Name != "alpha" || repos[1].Name != "beta" || repos[2].Name != "zeta" {
		t.Fatalf("unexpected sort order: %v, %v, %v", repos[0].Name, repos[1].Name, repos[2].Name)
	}
}
