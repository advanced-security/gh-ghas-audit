package collector

import (
	"testing"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
)

func TestUnsupportedLanguagesReportsGenuineCoverageGaps(t *testing.T) {
	source := apiRepository{}
	for _, name := range []string{"HTML", "CSS", "Scala", "Go", "Dockerfile", "Objective-C", "Shell", "PowerShell", "Batchfile"} {
		source.Languages.Nodes = append(source.Languages.Nodes, struct {
			Name string `json:"name"`
		}{Name: name})
	}

	got := unsupportedLanguages(source)

	// Go is analyzable, while HTML, CSS and Dockerfile are markup or build
	// description formats. Executable Shell and PowerShell source is reported.
	want := []string{"Batchfile", "Objective-C", "PowerShell", "Scala", "Shell"}
	if len(got) != len(want) {
		t.Fatalf("unsupportedLanguages = %v, want %v", got, want)
	}
	for index, name := range want {
		if got[index] != name {
			t.Errorf("position %d = %q, want %q", index, got[index], name)
		}
	}
}

func TestUnsupportedLanguagesIsEmptyWhenEverythingIsCovered(t *testing.T) {
	source := apiRepository{}
	for _, name := range []string{"Go", "Python", "HTML"} {
		source.Languages.Nodes = append(source.Languages.Nodes, struct {
			Name string `json:"name"`
		}{Name: name})
	}

	if got := unsupportedLanguages(source); len(got) != 0 {
		t.Fatalf("unsupportedLanguages = %v, want empty", got)
	}
}

func TestUnsupportedLanguagesSurfacedOnCollectedRepository(t *testing.T) {
	client := buildClient(t, scenario{
		name:      "mixed",
		languages: []string{"Scala", "HTML"},
		defaultSetup: defaultSetup{
			State: "configured",
		},
		workflows: workflowList{TotalCount: 0},
	})

	repo := findRepo(t, collect(t, client, Options{}), "mixed")

	if len(repo.UnsupportedLanguages) != 1 || repo.UnsupportedLanguages[0] != "Scala" {
		t.Fatalf("unsupported languages = %v, want [Scala]", repo.UnsupportedLanguages)
	}
	// Scala cannot be analyzed, so this is not a misconfiguration to chase.
	if repo.Status.Coverage != model.CoverageNoSupportedLanguages {
		t.Errorf("coverage = %q, want no-supported-languages", repo.Status.Coverage)
	}
}
