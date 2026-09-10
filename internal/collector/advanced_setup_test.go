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
	client := buildClient(t, scenario{
		name:         "advanced",
		languages:    []string{"JavaScript"},
		defaultSetup: defaultSetup{State: "not-configured"},
	})
	// CodeQL analyses exist, which is proof that scanning is happening.
	analysed := time.Now().Add(-48 * time.Hour)
	client.set("repos/"+testOrg+"/advanced/code-scanning/analyses", []codeScanningAnalysis{
		{Category: "/language:javascript-typescript", CreatedAt: &analysed, Results: 3},
	})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "advanced")

	if repo.Status.Configuration != model.ConfigAdvancedSetup {
		t.Fatalf("configuration = %q, want advanced-setup", repo.Status.Configuration)
	}
	if repo.Status.Overall == model.SeverityNotConfigured {
		t.Fatal("a repository scanning through advanced setup must not be reported as not configured")
	}
	// It must not be claimed healthy either, because its health was not
	// assessed.
	if repo.Status.Overall != model.SeverityUnknown {
		t.Fatalf("overall = %q, want unknown (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
	if model.NeedsAttention(repo.Status.Overall) {
		t.Error("an unevaluated repository must not be counted as needing attention")
	}
	if repo.LastSuccessfulScan == nil {
		t.Error("the last analysis date should be reported as evidence that scanning happens")
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
