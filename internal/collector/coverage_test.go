package collector

import (
	"testing"
	"time"

	"github.com/advanced-security/gh-ghas-audit/internal/model"
)

// The primary coverage signal needs no run history: compare the languages the
// repository contains against the languages default setup is configured for.
// Java and Kotlin both map to java-kotlin, JavaScript and TypeScript both map
// to javascript-typescript, and so on.
func TestUnscannedLanguageIsDetectedByComparingLanguagesToConfiguration(t *testing.T) {
	client := buildClient(t, scenario{
		name:      "kotlin-and-c",
		languages: []string{"Kotlin", "C", "CMake"},
		// Only C/C++ is configured, exactly as the API reports once Java and
		// Kotlin have been cleared from the configuration.
		defaultSetup: defaultSetup{State: "configured", Languages: []string{"c-cpp"}},
		workflows:    codeqlWorkflows(),
		runs:         map[string]any{"": runList("success", time.Hour)},
		jobs:         jobsFor(map[string]string{"c-cpp": "success"}),
		databases:    databasesFor([]string{"cpp"}, time.Hour),
	})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "kotlin-and-c")

	// Kotlin normalizes to java-kotlin and is not configured, so it is not
	// being scanned. CMake is not a CodeQL language and must be ignored.
	if !containsLanguage(repo.MissingLanguages, model.LangJavaKotlin) {
		t.Fatalf("missing languages = %v, want java-kotlin", repo.MissingLanguages)
	}
	if containsLanguage(repo.MissingLanguages, model.LangCCpp) {
		t.Errorf("c-cpp is configured and must not be reported missing, got %v", repo.MissingLanguages)
	}
	if repo.Status.Coverage != model.CoverageGap {
		t.Errorf("coverage = %q, want gap", repo.Status.Coverage)
	}
	if repo.Status.Overall != model.SeverityDegraded {
		t.Errorf("overall = %q, want degraded", repo.Status.Overall)
	}
}

// GitHub clears a language from default setup when its analysis fails, so the
// language runs once, fails, and is then silently dropped. Nothing else in the
// product surfaces that, so it is reported distinctly from a language that was
// simply never enabled.
func TestLanguageDroppedAfterFailingIsReportedDistinctly(t *testing.T) {
	client := buildClient(t, scenario{
		name:      "dropped",
		languages: []string{"Kotlin", "C"},
		// The configuration no longer lists java-kotlin.
		defaultSetup: defaultSetup{State: "configured", Languages: []string{"c-cpp"}},
		workflows:    codeqlWorkflows(),
		runs:         map[string]any{"": runList("success", time.Hour)},
		// But the latest run still contains its failed analysis job.
		jobs: jobsFor(map[string]string{
			"c-cpp":       "success",
			"java-kotlin": "failure",
		}),
		databases: databasesFor([]string{"cpp"}, time.Hour),
	})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "dropped")

	if !containsLanguage(repo.DeselectedLanguages, model.LangJavaKotlin) {
		t.Fatalf("deselected languages = %v, want java-kotlin", repo.DeselectedLanguages)
	}
	// It is still genuinely unconfigured, so the simple comparison must also
	// continue to report it.
	if !containsLanguage(repo.MissingLanguages, model.LangJavaKotlin) {
		t.Errorf("missing languages = %v, want java-kotlin; it is not configured", repo.MissingLanguages)
	}
	// A dropped language is more serious than one never enabled, because
	// nothing will scan it again.
	if repo.Status.Coverage != model.CoveragePartial {
		t.Errorf("coverage = %q, want partial", repo.Status.Coverage)
	}

	var found bool
	for _, diagnostic := range repo.Diagnostics {
		if diagnostic.Code == "language-auto-deselected" && diagnostic.Language == model.LangJavaKotlin {
			found = true
			if diagnostic.Severity != "error" {
				t.Errorf("severity = %q, want error", diagnostic.Severity)
			}
		}
		// The weaker message must not also be emitted for the same language.
		if diagnostic.Code == "language-not-configured" && diagnostic.Language == model.LangJavaKotlin {
			t.Error("a dropped language must not also be reported as merely not configured")
		}
	}
	if !found {
		t.Errorf("expected a language-auto-deselected diagnostic, got %+v", repo.Diagnostics)
	}
}

// A language that was never enabled has no analysis job, so it is a plain
// coverage gap rather than a silent drop.
func TestNeverEnabledLanguageIsNotReportedAsDropped(t *testing.T) {
	client := buildClient(t, scenario{
		name:         "never-enabled",
		languages:    []string{"Go", "Python"},
		defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
		workflows:    codeqlWorkflows(),
		runs:         map[string]any{"": runList("success", time.Hour)},
		jobs:         jobsFor(map[string]string{"go": "success"}),
		databases:    databasesFor([]string{"go"}, time.Hour),
	})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "never-enabled")

	if len(repo.DeselectedLanguages) != 0 {
		t.Fatalf("deselected languages = %v, want none", repo.DeselectedLanguages)
	}
	if !containsLanguage(repo.MissingLanguages, model.LangPython) {
		t.Errorf("missing languages = %v, want python", repo.MissingLanguages)
	}
	if repo.Status.Coverage != model.CoverageGap {
		t.Errorf("coverage = %q, want gap", repo.Status.Coverage)
	}

	for _, diagnostic := range repo.Diagnostics {
		if diagnostic.Code == "language-auto-deselected" {
			t.Error("a language that never ran must not be reported as dropped")
		}
	}
}

// When every language fails at setup the configuration is left empty, which is
// the case that looks enabled everywhere else while scanning nothing.
func TestEveryLanguageDroppedLeavesAnEmptyConfiguration(t *testing.T) {
	client := buildClient(t, scenario{
		name:      "all-dropped",
		languages: []string{"Kotlin"},
		// The API returns an empty language list in this state.
		defaultSetup: defaultSetup{State: "configured"},
		workflows:    codeqlWorkflows(),
		runs:         map[string]any{"": runList("failure", time.Hour)},
		jobs:         jobsFor(map[string]string{"java-kotlin": "failure"}),
	})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "all-dropped")

	if repo.Status.Overall != model.SeverityFailing {
		t.Fatalf("overall = %q, want failing", repo.Status.Overall)
	}
	if len(repo.ConfiguredLanguages) != 0 {
		t.Errorf("configured languages = %v, want none", repo.ConfiguredLanguages)
	}
	if !containsLanguage(repo.DeselectedLanguages, model.LangJavaKotlin) {
		t.Errorf("deselected languages = %v, want java-kotlin", repo.DeselectedLanguages)
	}
	if !containsLanguage(repo.MissingLanguages, model.LangJavaKotlin) {
		t.Errorf("missing languages = %v, want java-kotlin", repo.MissingLanguages)
	}
}

// Language aliases must resolve so the comparison is not defeated by naming.
func TestLanguageAliasesResolveForTheComparison(t *testing.T) {
	client := buildClient(t, scenario{
		name: "aliases",
		// Linguist names on the left, CodeQL identifiers in the configuration.
		languages: []string{"TypeScript", "Java"},
		defaultSetup: defaultSetup{
			State: "configured", Languages: []string{"javascript-typescript"},
		},
		workflows: codeqlWorkflows(),
		runs:      map[string]any{"": runList("success", time.Hour)},
		jobs:      jobsFor(map[string]string{"javascript-typescript": "success"}),
		databases: databasesFor([]string{"javascript"}, time.Hour),
	})

	repo := findRepo(t, collect(t, client, defaultActivityOptions()), "aliases")

	// TypeScript is covered by the javascript-typescript configuration.
	if containsLanguage(repo.MissingLanguages, model.LangJavaScriptTypeScript) {
		t.Errorf("typescript is covered by javascript-typescript, got missing = %v", repo.MissingLanguages)
	}
	// Java is not configured at all.
	if !containsLanguage(repo.MissingLanguages, model.LangJavaKotlin) {
		t.Errorf("missing languages = %v, want java-kotlin", repo.MissingLanguages)
	}
}
