package collector

import (
	"strings"
	"testing"
	"time"

	"github.com/advanced-security/gh-ghas-audit/internal/model"
)

// The default setup endpoint answers even when default setup is off, and the
// languages it returns are then an eligibility list rather than configuration.
// Recording them would invent configuration for a repository that has none,
// and the inflated "configured" list cancels out the detected languages so the
// rollout gap it exists to find disappears.
func TestUnconfiguredRepositoryReportsNoConfiguration(t *testing.T) {
	client := buildClient(t, scenario{
		name:      "eligible-not-configured",
		languages: []string{"Java"},
		defaultSetup: defaultSetup{
			State: "not-configured",
			// Exactly what GitHub returns: aliases of one another, which no
			// real configuration would contain together.
			Languages:   []string{"actions", "java-kotlin"},
			QuerySuite:  "default",
			ThreatModel: "remote",
			RunnerType:  "standard",
		},
	})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "eligible-not-configured")

	if len(repo.ConfiguredLanguages) != 0 {
		t.Fatalf("configured languages = %v, want none; the endpoint returns eligibility, not configuration",
			repo.ConfiguredLanguages)
	}
	if repo.Configuration.QuerySuite != "" || repo.Configuration.ThreatModel != "" || repo.Configuration.RunnerType != "" {
		t.Errorf("unconfigured repository reported configuration detail: suite=%q threat=%q runner=%q",
			repo.Configuration.QuerySuite, repo.Configuration.ThreatModel, repo.Configuration.RunnerType)
	}
	// The state itself is still reported, because that is a real fact.
	if repo.Configuration.DefaultSetupState != "not-configured" {
		t.Errorf("default setup state = %q, want not-configured", repo.Configuration.DefaultSetupState)
	}
	if repo.Status.Overall != model.SeverityNotConfigured {
		t.Fatalf("overall = %q, want not-configured", repo.Status.Overall)
	}
}

// A repository whose security configuration failed to attach still has a
// genuinely configured default setup, so its languages must survive. This is
// why the gate keys off the reported setup state rather than the classified
// configuration status.
func TestAttachFailedRepositoryKeepsItsConfiguredLanguages(t *testing.T) {
	client := buildClient(t, scenario{
		name:      "attach-failed",
		languages: []string{"Go"},
		defaultSetup: defaultSetup{
			State:     "configured",
			Languages: []string{"go"},
		},
		workflows:  codeqlWorkflows(),
		runs:       map[string]any{"": runList("success", time.Hour)},
		jobs:       jobsFor(map[string]string{"go": "success"}),
		databases:  databasesFor([]string{"go"}, time.Hour),
		attachment: "failed",
	})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "attach-failed")

	if !containsLanguage(repo.ConfiguredLanguages, model.LangGo) {
		t.Fatalf("configured languages = %v, want go; a failed attachment does not unconfigure default setup",
			repo.ConfiguredLanguages)
	}
}

// Config depth gathers no runtime evidence, so it can report a rollout gap but
// must never conclude a repository is healthy.
func TestConfigDepthNeverReportsHealthy(t *testing.T) {
	client := buildClient(t, scenario{
		name:      "config-only",
		languages: []string{"Go"},
		defaultSetup: defaultSetup{
			State:     "configured",
			Languages: []string{"go"},
		},
		workflows: codeqlWorkflows(),
		runs:      map[string]any{"": runList("success", time.Hour)},
		jobs:      jobsFor(map[string]string{"go": "success"}),
		databases: databasesFor([]string{"go"}, time.Hour),
	})

	options := defaultActivityOptions()
	options.Depth = DepthConfig
	repo := findRepo(t, collect(t, client, options), "config-only")

	if repo.Status.Overall == model.SeverityHealthy {
		t.Fatal("config depth reads no runtime evidence and must not report healthy")
	}
	if repo.Status.Execution != model.ExecNotEvaluated {
		t.Errorf("execution = %q, want not-evaluated", repo.Status.Execution)
	}

	// The same repository is healthy at health depth, proving the difference
	// is the evidence gathered rather than the repository.
	full := findRepo(t, collect(t, client, defaultActivityOptions()), "config-only")
	if full.Status.Overall != model.SeverityHealthy {
		t.Fatalf("health depth overall = %q, want healthy (reasons: %v)",
			full.Status.Overall, full.Status.Reasons)
	}
}

// Config depth still answers the question the original audit existed to
// answer: which supported languages are not configured for analysis.
func TestConfigDepthStillFindsRolloutGaps(t *testing.T) {
	client := buildClient(t, scenario{
		name:      "config-gap",
		languages: []string{"Go", "Python"},
		defaultSetup: defaultSetup{
			State:     "configured",
			Languages: []string{"go"},
		},
	})

	options := defaultActivityOptions()
	options.Depth = DepthConfig
	repo := findRepo(t, collect(t, client, options), "config-gap")

	if !containsLanguage(repo.MissingLanguages, model.LangPython) {
		t.Fatalf("missing languages = %v, want python", repo.MissingLanguages)
	}
	if repo.Status.Coverage != model.CoverageGap {
		t.Errorf("coverage = %q, want gap", repo.Status.Coverage)
	}
	if repo.Status.Overall != model.SeverityDegraded {
		t.Fatalf("overall = %q, want degraded (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
}

// Config depth must not spend requests on runtime evidence.
func TestConfigDepthDoesNotFetchRuntimeEvidence(t *testing.T) {
	client := buildClient(t, scenario{
		name:         "config-cheap",
		languages:    []string{"Go"},
		defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
		workflows:    codeqlWorkflows(),
		runs:         map[string]any{"": runList("success", time.Hour)},
	})

	options := defaultActivityOptions()
	options.Depth = DepthConfig
	collect(t, client, options)

	for _, request := range client.requests {
		for _, forbidden := range []string{"actions/workflows", "actions/runs", "code-scanning/analyses", "codeql/databases"} {
			if strings.Contains(request, forbidden) {
				t.Errorf("config depth requested runtime evidence: %s", request)
			}
		}
	}
}
