package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
)

func sampleDependabotReport() *model.DependabotReport {
	pushed := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	oldestAlert := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	oldestAlertDays := 12

	repos := []model.DependabotRepo{
		{
			Organization:  "acme",
			Name:          "payments",
			FullName:      "acme/payments",
			URL:           "https://github.com/acme/payments",
			Visibility:    "PRIVATE",
			DefaultBranch: "main",
			PushedAt:      timestampPtrForTest(pushed),
			Status: model.DependabotStatus{
				Overall:                   model.SeverityDegraded,
				DependencyGraph:           model.FeatureEnabled,
				DependencyGraphCoverage:   model.GraphCoveragePartial,
				DependabotAlerts:          model.FeatureEnabled,
				DependabotSecurityUpdates: model.FeatureEnabled,
				VersionUpdates:            model.VersionUpdatesConfigured,
				PullRequestHealth:         model.PRHealthHealthy,
				DependencyReview:          model.DependencyReviewNotEvaluated,
				Reasons: []string{
					"one or more manifests show only direct dependencies for an ecosystem that needs build-time " +
						"or lockfile resolution to see transitive dependencies, and no auto-submission workflow was found",
				},
			},
			DependencyGraph: model.DependencyGraphDetail{
				Evaluated:                  true,
				TotalManifests:             1,
				Ecosystems:                 []string{"maven"},
				ManifestsMissingTransitive: []string{"pom.xml"},
			},
			Alerts: model.AlertsDetail{
				Evaluated:      true,
				OpenTotal:      4,
				OpenCritical:   1,
				OpenHigh:       1,
				OpenMedium:     1,
				OpenLow:        1,
				OpenMalware:    1,
				OldestOpen:     timestampPtrForTest(oldestAlert),
				OldestOpenDays: &oldestAlertDays,
			},
			VersionUpdates: model.VersionUpdatesDetail{
				ConfigPath: ".github/dependabot.yml",
				Ecosystems: []string{"maven"},
			},
			PullRequests: model.PullRequestsDetail{Evaluated: true, Open: 1},
			Properties:   map[string]string{"application": "payments"},
		},
		{
			Organization:  "acme",
			Name:          "website",
			FullName:      "acme/website",
			URL:           "https://github.com/acme/website",
			Visibility:    "PUBLIC",
			DefaultBranch: "main",
			Status: model.DependabotStatus{
				Overall:                   model.SeverityHealthy,
				DependencyGraph:           model.FeatureEnabled,
				DependencyGraphCoverage:   model.GraphCoverageNotApplicable,
				DependabotAlerts:          model.FeatureEnabled,
				DependabotSecurityUpdates: model.FeatureEnabled,
				VersionUpdates:            model.VersionUpdatesConfigured,
				PullRequestHealth:         model.PRHealthNone,
				DependencyReview:          model.DependencyReviewEnforced,
			},
			DependencyGraph: model.DependencyGraphDetail{Evaluated: true, Ecosystems: []string{"npm"}},
			Alerts:          model.AlertsDetail{Evaluated: true},
			VersionUpdates:  model.VersionUpdatesDetail{ConfigPath: ".github/dependabot.yml", Ecosystems: []string{"npm"}},
			PullRequests:    model.PullRequestsDetail{Evaluated: true},
			Properties:      map[string]string{"application": "web"},
		},
	}

	return &model.DependabotReport{
		SchemaVersion: model.DependabotSchemaVersion,
		GeneratedAt:   time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC),
		Tool:          model.ToolInfo{Name: "gh-ghas-audit", Version: "test"},
		Scope:         model.Scope{Host: "github.com", Organizations: []string{"acme"}},
		Settings:      model.DependabotSettings{Concurrency: 8, ScanDepth: "health"},
		Repositories:  repos,
		Summary:       model.BuildDependabotSummary(repos),
		Organizations: model.BuildDependabotOrgReports(repos),
	}
}

func timestampPtrForTest(t time.Time) *model.Timestamp {
	converted := model.Timestamp(t)
	return &converted
}

func TestWriteDependabotJSONRoundTrips(t *testing.T) {
	var buffer bytes.Buffer
	if err := WriteDependabotJSON(&buffer, sampleDependabotReport()); err != nil {
		t.Fatalf("WriteDependabotJSON returned an error: %v", err)
	}

	var decoded model.DependabotReport
	if err := json.Unmarshal(buffer.Bytes(), &decoded); err != nil {
		t.Fatalf("emitted JSON is not parseable: %v", err)
	}
	if decoded.SchemaVersion != model.DependabotSchemaVersion {
		t.Errorf("schema version = %q, want %q", decoded.SchemaVersion, model.DependabotSchemaVersion)
	}
	if len(decoded.Repositories) != 2 {
		t.Fatalf("got %d repositories, want 2", len(decoded.Repositories))
	}
	if decoded.Repositories[0].Status.DependencyGraphCoverage != model.GraphCoveragePartial {
		t.Errorf("coverage did not survive the round trip: %q", decoded.Repositories[0].Status.DependencyGraphCoverage)
	}
	if len(decoded.Repositories[0].DependencyGraph.ManifestsMissingTransitive) != 1 {
		t.Error("manifest gap detail must survive the round trip")
	}
}

func TestWriteDependabotNDJSONEmitsHeaderThenRepositories(t *testing.T) {
	var buffer bytes.Buffer
	if err := WriteDependabotNDJSON(&buffer, sampleDependabotReport()); err != nil {
		t.Fatalf("WriteDependabotNDJSON returned an error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buffer.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 1 header and 2 repositories", len(lines))
	}

	var header struct {
		Type          string `json:"type"`
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &header); err != nil {
		t.Fatalf("header line is not valid JSON: %v", err)
	}
	if header.Type != "report" || header.SchemaVersion != model.DependabotSchemaVersion {
		t.Fatalf("unexpected header %+v", header)
	}

	for _, line := range lines[1:] {
		var record struct {
			Type     string `json:"type"`
			FullName string `json:"full_name"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("repository line is not valid JSON: %v", err)
		}
		if record.Type != "repository" || record.FullName == "" {
			t.Fatalf("unexpected repository record %+v", record)
		}
	}
}

func TestWriteDependabotCSVIncludesEvidenceColumns(t *testing.T) {
	var buffer bytes.Buffer
	if err := WriteDependabotCSV(&buffer, sampleDependabotReport()); err != nil {
		t.Fatalf("WriteDependabotCSV returned an error: %v", err)
	}

	records, err := csv.NewReader(&buffer).ReadAll()
	if err != nil {
		t.Fatalf("emitted CSV is not parseable: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("got %d rows, want a header and 2 repositories", len(records))
	}

	index := map[string]int{}
	for position, name := range records[0] {
		index[name] = position
	}
	row := records[1]

	if row[index["Overall status"]] != string(model.SeverityDegraded) {
		t.Errorf("overall status = %q", row[index["Overall status"]])
	}
	if row[index["Dependency graph coverage"]] != string(model.GraphCoveragePartial) {
		t.Errorf("dependency graph coverage = %q", row[index["Dependency graph coverage"]])
	}
	if row[index["Manifests missing transitive deps"]] != "pom.xml" {
		t.Errorf("manifests missing transitive deps = %q, want pom.xml", row[index["Manifests missing transitive deps"]])
	}
	if row[index["Open alerts"]] != "4" {
		t.Errorf("open alerts = %q, want 4", row[index["Open alerts"]])
	}
	if row[index["Open critical alerts"]] != "1" {
		t.Errorf("open critical alerts = %q, want 1", row[index["Open critical alerts"]])
	}
	if row[index["Open medium alerts"]] != "1" {
		t.Errorf("open medium alerts = %q, want 1", row[index["Open medium alerts"]])
	}
	if row[index["Open low alerts"]] != "1" {
		t.Errorf("open low alerts = %q, want 1", row[index["Open low alerts"]])
	}
	if row[index["Open malware alerts"]] != "1" {
		t.Errorf("open malware alerts = %q, want 1", row[index["Open malware alerts"]])
	}
	if row[index["Evidence complete"]] != "true" {
		t.Errorf("evidence complete = %q, want true", row[index["Evidence complete"]])
	}
}

// A repository whose evidence could not be fully collected must be marked, so
// a spreadsheet reader does not treat it as a clean result.
func TestWriteDependabotCSVMarksIncompleteEvidence(t *testing.T) {
	report := sampleDependabotReport()
	report.Repositories[1].Status.Incomplete = true
	report.Repositories[1].Errors = []string{"dependency graph manifests: HTTP 403"}

	var buffer bytes.Buffer
	if err := WriteDependabotCSV(&buffer, report); err != nil {
		t.Fatalf("WriteDependabotCSV returned an error: %v", err)
	}

	records, err := csv.NewReader(&buffer).ReadAll()
	if err != nil {
		t.Fatalf("emitted CSV is not parseable: %v", err)
	}
	index := map[string]int{}
	for position, name := range records[0] {
		index[name] = position
	}
	if records[2][index["Evidence complete"]] != "false" {
		t.Errorf("evidence complete = %q, want false", records[2][index["Evidence complete"]])
	}
	if records[2][index["Errors"]] == "" {
		t.Error("the collection error must be exported so the gap is visible")
	}
}

func TestWriteDependabotTableHandlesEmptyResults(t *testing.T) {
	report := sampleDependabotReport()
	report.Repositories = nil
	report.Summary = model.BuildDependabotSummary(nil)

	var buffer bytes.Buffer
	if err := WriteDependabotTable(&buffer, report, TableOptions{}); err != nil {
		t.Fatalf("WriteDependabotTable returned an error: %v", err)
	}
	if !strings.Contains(buffer.String(), "No repositories matched") {
		t.Errorf("empty result set should explain itself, got %q", buffer.String())
	}
}

func TestWriteDependabotTableHighlightsProblems(t *testing.T) {
	var buffer bytes.Buffer
	if err := WriteDependabotTable(&buffer, sampleDependabotReport(), TableOptions{Detailed: true}); err != nil {
		t.Fatalf("WriteDependabotTable returned an error: %v", err)
	}
	output := buffer.String()
	if !strings.Contains(output, "acme/payments") || !strings.Contains(output, "acme/website") {
		t.Fatalf("table is missing expected repositories: %q", output)
	}
	if !strings.Contains(output, string(model.SeverityDegraded)) {
		t.Errorf("table should show the degraded status, got %q", output)
	}
	if !strings.Contains(output, "no auto-submission workflow was found") {
		t.Errorf("--detailed output should include the reason, got %q", output)
	}
}

func TestResolveDependabotPropertyColumnsUsesDiscoveredNames(t *testing.T) {
	report := sampleDependabotReport()
	if got := ResolveDependabotPropertyColumns(report, nil); len(got) != 1 || got[0] != "application" {
		t.Fatalf("discovered property columns = %v, want [application]", got)
	}
	if got := ResolveDependabotPropertyColumns(report, []string{"team"}); len(got) != 1 || got[0] != "team" {
		t.Fatalf("explicit property columns = %v, want [team]", got)
	}
	report.Repositories = nil
	if got := ResolveDependabotPropertyColumns(report, nil); got != nil {
		t.Fatalf("no repositories should yield no property columns, got %v", got)
	}
}

// TestResolveDependabotPropertyColumnsIsDeterministicallySorted verifies
// that discovered property columns, across several differently-cased
// property names, always come back in the same sorted order (and with the
// same lexicographically-smallest casing chosen per folded name) regardless
// of Go's randomized map iteration order — this is user-facing table/json/csv
// column output, so its ordering must be stable across runs.
func TestResolveDependabotPropertyColumnsIsDeterministicallySorted(t *testing.T) {
	report := &model.DependabotReport{
		Repositories: []model.DependabotRepo{
			{Properties: map[string]string{"Zebra": "z", "apple": "a"}},
			{Properties: map[string]string{"Mango": "m", "APPLE": "a2"}},
		},
	}
	for attempt := 0; attempt < 20; attempt++ {
		got := ResolveDependabotPropertyColumns(report, nil)
		want := []string{"APPLE", "Mango", "Zebra"}
		if len(got) != len(want) {
			t.Fatalf("attempt %d: property columns = %v, want %v", attempt, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("attempt %d: property columns = %v, want %v (sorted, lexicographically-smallest casing per name)",
					attempt, got, want)
			}
		}
	}
}
