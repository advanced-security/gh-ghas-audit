package collector

import (
	"testing"
	"time"

	"github.com/advanced-security/gh-ghas-audit/internal/model"
)

// activityScenario builds a configured repository whose last successful scan
// and last push are both a known age.
func activityScenario(name string, scanAge, pushAge time.Duration) scenario {
	return scenario{
		name:         name,
		languages:    []string{"Go"},
		pushedAt:     pushAge,
		defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
		workflows:    codeqlWorkflows(),
		runs:         map[string]any{"": runList("success", scanAge)},
		jobs:         jobsFor(map[string]string{"go": "success"}),
		databases:    databasesFor([]string{"go"}, scanAge),
	}
}

const (
	day      = 24 * time.Hour
	sixMonth = 180 * day
)

func defaultActivityOptions() Options {
	return Options{
		StaleAfter:         8 * day,
		StaleAfterInactive: 32 * day,
		InactiveAfter:      sixMonth,
	}
}

// GitHub scans repositories with no recent pushes every 30 days. Judging those
// against the weekly threshold would report them stale for 23 days out of
// every 30, which is the false positive this tier exists to prevent.
func TestInactiveRepositoryIsNotStaleWithinTheMonthlyWindow(t *testing.T) {
	client := buildClient(t, activityScenario("dormant", 20*day, 400*day))

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "dormant")

	if repo.Activity != model.ActivityInactive {
		t.Fatalf("activity = %q, want inactive", repo.Activity)
	}
	if repo.Status.Freshness != model.FreshCurrent {
		t.Fatalf("freshness = %q, want current; 20 days is inside the monthly window", repo.Status.Freshness)
	}
	if repo.Status.Overall != model.SeverityHealthy {
		t.Fatalf("overall = %q, want healthy (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
	if repo.StaleAfter != "32d (inactive)" {
		t.Errorf("stale after = %q, want the inactive threshold", repo.StaleAfter)
	}
}

// The same age on an active repository is a real problem, because it should
// have scanned weekly.
func TestActiveRepositoryIsStaleAtTheSameAge(t *testing.T) {
	client := buildClient(t, activityScenario("busy", 20*day, 10*day))

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "busy")

	if repo.Activity != model.ActivityActive {
		t.Fatalf("activity = %q, want active", repo.Activity)
	}
	if repo.Status.Overall != model.SeverityStale {
		t.Fatalf("overall = %q, want stale", repo.Status.Overall)
	}
	if repo.StaleAfter != "8d" {
		t.Errorf("stale after = %q, want 8d", repo.StaleAfter)
	}
}

func TestInactiveRepositoryIsStaleBeyondTheMonthlyWindow(t *testing.T) {
	client := buildClient(t, activityScenario("abandoned", 200*day, 400*day))

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "abandoned")

	if repo.Status.Overall != model.SeverityStale {
		t.Fatalf("overall = %q, want stale", repo.Status.Overall)
	}
	// The reason must explain the monthly schedule, otherwise this looks like
	// a repository that missed a weekly scan.
	var explained bool
	for _, reason := range repo.Status.Reasons {
		if contains(reason, "monthly") && contains(reason, "32d") {
			explained = true
		}
	}
	if !explained {
		t.Errorf("stale reason must name the monthly schedule and threshold, got %v", repo.Status.Reasons)
	}
}

// The boundary must be exact, since it decides which threshold applies.
func TestActivityBoundaryAtTheInactivityWindow(t *testing.T) {
	cases := []struct {
		name    string
		pushAge time.Duration
		want    model.Activity
	}{
		{"just-active", sixMonth - day, model.ActivityActive},
		{"just-inactive", sixMonth + day, model.ActivityInactive},
	}

	for _, test := range cases {
		client := buildClient(t, activityScenario(test.name, time.Hour, test.pushAge))
		repo := findRepo(t, collect(t, client, defaultActivityOptions()), test.name)
		if repo.Activity != test.want {
			t.Errorf("%s: activity = %q, want %q", test.name, repo.Activity, test.want)
		}
	}
}

// An organization that has not enabled monthly scanning of inactive
// repositories does not want them reported stale forever.
func TestInactiveStalenessCanBeDisabled(t *testing.T) {
	client := buildClient(t, activityScenario("dormant", 500*day, 400*day))

	options := defaultActivityOptions()
	options.StaleAfterInactive = 0

	repo := findRepo(t, collect(t, client, options), "dormant")

	if repo.Status.Freshness != model.FreshCurrent {
		t.Fatalf("freshness = %q, want current when the inactive check is off", repo.Status.Freshness)
	}
	if repo.Status.Overall != model.SeverityHealthy {
		t.Fatalf("overall = %q, want healthy", repo.Status.Overall)
	}
	if repo.StaleAfter != "not checked (inactive)" {
		t.Errorf("stale after = %q, want it to say the check was skipped", repo.StaleAfter)
	}
	// The scan age is still recorded, so the data is available even when it
	// does not drive a verdict.
	if repo.StaleDays == nil || *repo.StaleDays < 490 {
		t.Errorf("scan age must still be reported, got %v", repo.StaleDays)
	}
}

// Turning off activity classification restores the single-threshold behaviour.
func TestActivityClassificationCanBeDisabled(t *testing.T) {
	client := buildClient(t, activityScenario("dormant", 20*day, 400*day))

	options := defaultActivityOptions()
	options.InactiveAfter = 0

	repo := findRepo(t, collect(t, client, options), "dormant")

	if repo.Activity != model.ActivityActive {
		t.Fatalf("activity = %q, want active when classification is disabled", repo.Activity)
	}
	if repo.Status.Overall != model.SeverityStale {
		t.Fatalf("overall = %q, want stale under the weekly threshold", repo.Status.Overall)
	}
}

// A repository with no push history cannot be classified, and must not be
// quietly given the more permissive monthly threshold.
func TestUnknownPushHistoryUsesTheActiveThreshold(t *testing.T) {
	scene := activityScenario("no-history", 20*day, 0)
	scene.noPushedAt = true
	client := buildClient(t, scene)

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "no-history")

	if repo.Activity != model.ActivityUnknown {
		t.Fatalf("activity = %q, want unknown", repo.Activity)
	}
	if repo.Status.Overall != model.SeverityStale {
		t.Fatalf("overall = %q, want stale; unknown activity must not relax the threshold", repo.Status.Overall)
	}
}

func TestDaysSincePushIsReported(t *testing.T) {
	client := buildClient(t, activityScenario("tracked", time.Hour, 45*day))

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "tracked")

	if repo.DaysSincePush == nil {
		t.Fatal("days since push must be reported so activity can be audited")
	}
	if *repo.DaysSincePush < 44 || *repo.DaysSincePush > 46 {
		t.Errorf("days since push = %d, want about 45", *repo.DaysSincePush)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 ||
		indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for index := 0; index+len(needle) <= len(haystack); index++ {
		if haystack[index:index+len(needle)] == needle {
			return index
		}
	}
	return -1
}
