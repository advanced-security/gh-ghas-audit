package collector

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/advanced-security/gh-ghas-audit/internal/ghapi"
	"github.com/advanced-security/gh-ghas-audit/internal/model"
)

// A transient rate limit says nothing about a repository. Reporting it as a
// health verdict would quietly blank out large parts of an estate while the
// report still claimed to be complete.
func TestRateLimitIsNotReportedAsRepositoryHealth(t *testing.T) {
	client := buildClient(t, scenario{name: "throttled", languages: []string{"Go"}})
	client.set("repos/"+testOrg+"/throttled/code-scanning/default-setup", &ghapi.StatusError{
		StatusCode:  http.StatusForbidden,
		Message:     "You have exceeded a secondary rate limit",
		URL:         "repos/test-org/throttled/code-scanning/default-setup",
		RateLimited: true,
	})

	report := collect(t, client, Options{})
	repo := findRepo(t, report, "throttled")

	if repo.Status.Configuration == model.ConfigUnavailable {
		t.Fatal("a rate limit must not be reported as the repository being unavailable")
	}
	if repo.Status.Configuration != model.ConfigUnknown {
		t.Errorf("configuration = %q, want unknown", repo.Status.Configuration)
	}
	if len(repo.Errors) == 0 {
		t.Error("a rate limit must be recorded as a collection error")
	}
	if !repo.Status.Incomplete {
		t.Error("a repository whose evidence could not be read must be marked incomplete")
	}
	if !report.Stats.Incomplete {
		t.Error("the report must be marked incomplete so it is not read as authoritative")
	}
}

// A licensing 403 is a durable fact about the repository and should stay a
// clean "unavailable" without being treated as a collection failure.
func TestUnlicensedRepositoryIsNotTreatedAsACollectionError(t *testing.T) {
	client := buildClient(t, scenario{name: "unlicensed", languages: []string{"Go"}})
	client.set("repos/"+testOrg+"/unlicensed/code-scanning/default-setup", &ghapi.StatusError{
		StatusCode: http.StatusForbidden,
		Message:    "Advanced Security must be enabled for this repository",
		URL:        "repos/test-org/unlicensed/code-scanning/default-setup",
	})

	repo := findRepo(t, collect(t, client, Options{}), "unlicensed")

	if repo.Status.Configuration != model.ConfigUnavailable {
		t.Errorf("configuration = %q, want unavailable", repo.Status.Configuration)
	}
	if len(repo.Errors) != 0 {
		t.Errorf("a licensing error is not a collection failure, got %v", repo.Errors)
	}
}

// A repository must never be asserted healthy on the strength of a check that
// did not actually run.
func TestIncompleteEvidenceIsNeverReportedHealthy(t *testing.T) {
	client := buildClient(t, scenario{
		name:      "jobs-unreadable",
		languages: []string{"Go"},
		defaultSetup: defaultSetup{
			State: "configured", Languages: []string{"go"},
		},
		workflows: codeqlWorkflows(),
		runs: map[string]any{
			"": runList("success", time.Hour),
		},
		// No jobs response is registered, and the databases below would
		// otherwise be used to infer that every language succeeded.
		databases: databasesFor([]string{"go"}, time.Hour),
	})
	client.set("repos/"+testOrg+"/jobs-unreadable/actions/runs/", &ghapi.StatusError{
		StatusCode: http.StatusForbidden,
		Message:    "Resource not accessible by integration",
		URL:        "repos/test-org/jobs-unreadable/actions/runs/1234/jobs",
	})

	repo := findRepo(t, collect(t, client, Options{}), "jobs-unreadable")

	if repo.Status.Overall == model.SeverityHealthy {
		t.Fatal("a repository whose job evidence could not be read must not be reported healthy")
	}
	if !repo.Status.Incomplete {
		t.Error("the repository must be marked incomplete")
	}
	if len(repo.SucceededLanguages) != 0 {
		t.Errorf("stale CodeQL databases must not imply success when jobs failed, got %v", repo.SucceededLanguages)
	}
}

// When jobs are genuinely absent rather than unreadable, CodeQL databases are
// the only remaining evidence and should still be used.
func TestDatabasesProvideEvidenceWhenJobsAreGenuinelyAbsent(t *testing.T) {
	client := buildClient(t, scenario{
		name:      "aged-out",
		languages: []string{"Go"},
		defaultSetup: defaultSetup{
			State: "configured", Languages: []string{"go"},
		},
		workflows: codeqlWorkflows(),
		runs: map[string]any{
			"": runList("success", time.Hour),
		},
		jobs:      jobList{TotalCount: 0},
		databases: databasesFor([]string{"go"}, time.Hour),
	})

	repo := findRepo(t, collect(t, client, Options{}), "aged-out")

	if repo.Status.Overall != model.SeverityHealthy {
		t.Fatalf("overall = %q, want healthy (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
	if len(repo.SucceededLanguages) != 1 {
		t.Errorf("succeeded languages = %v, want [go]", repo.SucceededLanguages)
	}
}

// Failing to evaluate a filter must not silently produce an empty report,
// which would look identical to a clean bill of health.
func TestSecurityConfigurationFilterFailsLoudlyWhenUnavailable(t *testing.T) {
	client := buildClient(t, scenario{name: "any", languages: []string{"Go"}})
	client.set("orgs/"+testOrg+"/code-security/configurations?", &ghapi.StatusError{
		StatusCode: http.StatusForbidden,
		Message:    "Resource not accessible by integration",
		URL:        "orgs/test-org/code-security/configurations",
	})

	options := Options{
		Organizations:         []string{testOrg},
		SecurityConfiguration: "Production",
		StaleAfter:            8 * 24 * time.Hour,
		Concurrency:           1,
	}
	report, err := New(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}

	if len(report.Repositories) != 0 {
		t.Fatalf("expected no repositories, got %d", len(report.Repositories))
	}
	if len(report.Warnings) == 0 {
		t.Fatal("an unusable filter must be reported, not silently applied to nothing")
	}
	if !strings.Contains(strings.Join(report.Warnings, " "), "security-configuration") {
		t.Errorf("the warning must name the flag that could not be applied, got %v", report.Warnings)
	}
	if !report.Stats.Incomplete {
		t.Error("the report must be marked incomplete")
	}
}

func TestPropertyFilterFailsLoudlyWhenUnavailable(t *testing.T) {
	client := buildClient(t, scenario{name: "any", languages: []string{"Go"}})
	client.set("orgs/"+testOrg+"/properties/values?", &ghapi.StatusError{
		StatusCode: http.StatusForbidden,
		Message:    "Resource not accessible by integration",
		URL:        "orgs/test-org/properties/values",
	})

	options := Options{
		Organizations:   []string{testOrg},
		PropertyFilters: map[string][]string{"application": {"payments"}},
		StaleAfter:      8 * 24 * time.Hour,
		Concurrency:     1,
	}
	report, err := New(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}

	if len(report.Warnings) == 0 {
		t.Fatal("an unusable property filter must be reported")
	}
	if !strings.Contains(strings.Join(report.Warnings, " "), "property-filter") {
		t.Errorf("the warning must name the flag that could not be applied, got %v", report.Warnings)
	}
}

// Grouping is presentational, so it should degrade to "(not set)" rather than
// failing the scan.
func TestGroupingDegradesWhenPropertiesAreUnavailable(t *testing.T) {
	client := buildClient(t, scenario{
		name: "grouped", languages: []string{"Go"},
		defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
		workflows:    codeqlWorkflows(),
		runs:         map[string]any{"": runList("success", time.Hour)},
		jobs:         jobsFor(map[string]string{"go": "success"}),
		databases:    databasesFor([]string{"go"}, time.Hour),
	})
	client.set("orgs/"+testOrg+"/properties/values?", &ghapi.StatusError{
		StatusCode: http.StatusForbidden,
		Message:    "Resource not accessible by integration",
		URL:        "orgs/test-org/properties/values",
	})

	report := collect(t, client, Options{GroupByProperty: "application"})

	if len(report.Repositories) != 1 {
		t.Fatalf("grouping must not exclude repositories, got %d", len(report.Repositories))
	}
	if len(report.Summary.Groups) != 1 || report.Summary.Groups[0].Value != "(not set)" {
		t.Errorf("expected a single (not set) group, got %+v", report.Summary.Groups)
	}
}

// filterProperties must copy before appending, or concurrent workers would
// write into the flag parser's shared backing array.
func TestFilterPropertiesDoesNotMutateOptions(t *testing.T) {
	// A slice with spare capacity, as produced by a repeated string slice flag.
	backing := make([]string, 2, 8)
	backing[0] = "application"
	backing[1] = "tier"

	collector := New(newFakeClient(), Options{
		Properties:      backing,
		PropertyFilters: map[string][]string{"owner": {"team"}, "region": {"eu"}},
	})

	for attempt := 0; attempt < 50; attempt++ {
		collector.filterProperties(map[string]string{"application": "payments"})
	}

	if backing[0] != "application" || backing[1] != "tier" {
		t.Fatalf("filterProperties mutated the caller's slice: %v", backing[:2])
	}
	if len(backing) != 2 {
		t.Fatalf("filterProperties changed the caller's slice length to %d", len(backing))
	}
}
