package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
)

func sampleReport() *model.Report {
	scanned := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	staleDays := 8
	runStarted := scanned

	repos := []model.Repo{
		{
			Organization:  "acme",
			Name:          "payments",
			FullName:      "acme/payments",
			URL:           "https://github.com/acme/payments",
			Visibility:    "private",
			DefaultBranch: "main",
			Status: model.Status{
				Overall:       model.SeverityDegraded,
				Configuration: model.ConfigConfigured,
				Execution:     model.ExecSuccess,
				Freshness:     model.FreshCurrent,
				Coverage:      model.CoveragePartial,
				Reasons:       []string{"one or more configured languages are not being analyzed successfully"},
			},
			Configuration: model.ConfigDetail{
				DefaultSetupState: "configured",
				Schedule:          "weekly",
				QuerySuite:        "default",
			},
			Execution: model.ExecutionDetail{
				LatestCompletedRun: &model.RunRef{
					ID: 42, Conclusion: "success", StartedAt: &runStarted,
					URL: "https://github.com/acme/payments/actions/runs/42",
				},
			},
			DetectedLanguages:   []model.Language{model.LangJavaKotlin, model.LangPython},
			ConfiguredLanguages: []model.Language{model.LangJavaKotlin, model.LangPython},
			SucceededLanguages:  []model.Language{model.LangJavaKotlin},
			FailedLanguages:     []model.Language{model.LangPython},
			LastSuccessfulScan:  &scanned,
			StaleDays:           &staleDays,
			Languages: []model.LanguageState{
				{Language: model.LangJavaKotlin, Detected: true, Configured: true, Analyzed: true, Succeeded: true, JobConclusion: "success"},
				{Language: model.LangPython, Detected: true, Configured: true, Analyzed: true, JobConclusion: "failure"},
			},
			Properties: map[string]string{"application": "payments"},
			Diagnostics: []model.Diagnostic{
				{Source: model.SourceAPI, Severity: "warning", Code: "language-not-analyzed", Language: model.LangPython,
					Message: "the latest analysis run succeeded but python produced no successful analysis"},
			},
		},
		{
			Organization:  "acme",
			Name:          "website",
			FullName:      "acme/website",
			URL:           "https://github.com/acme/website",
			Visibility:    "public",
			DefaultBranch: "main",
			Status: model.Status{
				Overall:       model.SeverityHealthy,
				Configuration: model.ConfigConfigured,
				Execution:     model.ExecSuccess,
				Freshness:     model.FreshCurrent,
				Coverage:      model.CoverageComplete,
			},
			ConfiguredLanguages: []model.Language{model.LangJavaScriptTypeScript},
			SucceededLanguages:  []model.Language{model.LangJavaScriptTypeScript},
			LastSuccessfulScan:  &scanned,
			Languages: []model.LanguageState{
				{Language: model.LangJavaScriptTypeScript, Detected: true, Configured: true, Analyzed: true, Succeeded: true, JobConclusion: "success"},
			},
			Properties: map[string]string{"application": "web"},
		},
	}

	return &model.Report{
		SchemaVersion: model.SchemaVersion,
		GeneratedAt:   time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC),
		Tool:          model.ToolInfo{Name: "gh-ghas-audit", Version: "test"},
		Scope:         model.Scope{Host: "github.com", Organizations: []string{"acme"}},
		Settings:      model.Settings{StaleAfter: "8d", Concurrency: 8, GroupByProperty: "application"},
		Repositories:  repos,
		Summary:       model.BuildSummary(repos, "application"),
		Organizations: model.BuildOrgReports(repos),
	}
}

func TestParseFormat(t *testing.T) {
	cases := map[string]Format{
		"table":         FormatTable,
		"JSON":          FormatJSON,
		"ndjson":        FormatNDJSON,
		"csv":           FormatCSV,
		"language-csv":  FormatLanguageCSV,
		"languages-csv": FormatLanguageCSV,
	}
	for input, want := range cases {
		got, err := ParseFormat(input)
		if err != nil || got != want {
			t.Errorf("ParseFormat(%q) = %q, %v; want %q", input, got, err, want)
		}
	}

	if _, err := ParseFormat("xml"); err == nil {
		t.Error("unsupported formats must be rejected")
	}
}

func TestWriteJSONRoundTrips(t *testing.T) {
	var buffer bytes.Buffer
	if err := WriteJSON(&buffer, sampleReport()); err != nil {
		t.Fatalf("WriteJSON returned an error: %v", err)
	}

	var decoded model.Report
	if err := json.Unmarshal(buffer.Bytes(), &decoded); err != nil {
		t.Fatalf("emitted JSON is not parseable: %v", err)
	}
	if decoded.SchemaVersion != model.SchemaVersion {
		t.Errorf("schema version = %q, want %q", decoded.SchemaVersion, model.SchemaVersion)
	}
	if len(decoded.Repositories) != 2 {
		t.Fatalf("got %d repositories, want 2", len(decoded.Repositories))
	}
	if decoded.Repositories[0].Status.Coverage != model.CoveragePartial {
		t.Errorf("coverage did not survive the round trip: %q", decoded.Repositories[0].Status.Coverage)
	}
	if len(decoded.Repositories[0].Languages) != 2 {
		t.Error("per-language detail must survive the round trip")
	}
}

func TestWriteNDJSONEmitsHeaderThenRepositories(t *testing.T) {
	var buffer bytes.Buffer
	if err := WriteNDJSON(&buffer, sampleReport()); err != nil {
		t.Fatalf("WriteNDJSON returned an error: %v", err)
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
	if header.Type != "report" || header.SchemaVersion != model.SchemaVersion {
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

func TestWriteNDJSONPreservesOrganizationErrorsWithoutRepositories(t *testing.T) {
	report := &model.Report{
		SchemaVersion: model.SchemaVersion,
		Organizations: []model.OrgReport{
			{Login: "unreadable", BySeverity: map[string]int{}, Error: "organization could not be read: 403 Forbidden"},
		},
		Stats: model.Stats{Incomplete: true},
	}
	var canonical, streamed bytes.Buffer
	if err := WriteJSON(&canonical, report); err != nil {
		t.Fatal(err)
	}
	if err := WriteNDJSON(&streamed, report); err != nil {
		t.Fatal(err)
	}
	var want model.Report
	if err := json.Unmarshal(canonical.Bytes(), &want); err != nil {
		t.Fatal(err)
	}
	var header struct {
		Type          string            `json:"type"`
		Organizations []model.OrgReport `json:"organizations"`
	}
	decoder := json.NewDecoder(&streamed)
	if err := decoder.Decode(&header); err != nil {
		t.Fatal(err)
	}
	if header.Type != "report" || !reflect.DeepEqual(header.Organizations, want.Organizations) {
		t.Fatalf("NDJSON header lost canonical organization data: %+v; want %+v", header, want.Organizations)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("an empty report must emit only the header, got %v", err)
	}
}

func TestWriteCSVIncludesEvidenceColumns(t *testing.T) {
	var buffer bytes.Buffer
	if err := WriteCSV(&buffer, sampleReport(), []string{"application"}); err != nil {
		t.Fatalf("WriteCSV returned an error: %v", err)
	}

	records, err := csv.NewReader(&buffer).ReadAll()
	if err != nil {
		t.Fatalf("emitted CSV is not parseable: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("got %d rows, want a header and 2 repositories", len(records))
	}

	header := records[0]
	if header[len(header)-1] != "Property: application" {
		t.Errorf("property column missing, header ends with %q", header[len(header)-1])
	}

	index := map[string]int{}
	for position, name := range header {
		index[name] = position
	}
	row := records[1]

	if row[index["Overall status"]] != string(model.SeverityDegraded) {
		t.Errorf("overall status = %q", row[index["Overall status"]])
	}
	if row[index["Languages not analyzed"]] != "python" {
		t.Errorf("languages not analyzed = %q, want python", row[index["Languages not analyzed"]])
	}
	if row[index["Last successful scan"]] != "2026-09-01T12:00:00Z" {
		t.Errorf("last successful scan = %q", row[index["Last successful scan"]])
	}
	if row[index["Days since last scan"]] != "8" {
		t.Errorf("days since last scan = %q, want 8", row[index["Days since last scan"]])
	}
	if !strings.Contains(row[index["Latest run URL"]], "/actions/runs/42") {
		t.Errorf("evidence URL missing, got %q", row[index["Latest run URL"]])
	}
	if row[index["Property: application"]] != "payments" {
		t.Errorf("property value = %q, want payments", row[index["Property: application"]])
	}
	if row[index["Evidence complete"]] != "true" {
		t.Errorf("evidence complete = %q, want true", row[index["Evidence complete"]])
	}
}

// A repository whose evidence could not be fully collected must be marked, so
// a spreadsheet reader does not treat it as a clean result.
func TestWriteCSVMarksIncompleteEvidence(t *testing.T) {
	report := sampleReport()
	report.Repositories[1].Status.Incomplete = true
	report.Repositories[1].Errors = []string{"run jobs: HTTP 403"}

	var buffer bytes.Buffer
	if err := WriteCSV(&buffer, report, nil); err != nil {
		t.Fatalf("WriteCSV returned an error: %v", err)
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

func TestWriteLanguageCSVEmitsOneRowPerLanguage(t *testing.T) {
	var buffer bytes.Buffer
	if err := WriteLanguageCSV(&buffer, sampleReport(), []string{"application"}); err != nil {
		t.Fatalf("WriteLanguageCSV returned an error: %v", err)
	}

	records, err := csv.NewReader(&buffer).ReadAll()
	if err != nil {
		t.Fatalf("emitted CSV is not parseable: %v", err)
	}
	// Two languages for payments, one for website, plus the header.
	if len(records) != 4 {
		t.Fatalf("got %d rows, want 4", len(records))
	}

	index := map[string]int{}
	for position, name := range records[0] {
		index[name] = position
	}

	var pythonRow []string
	for _, row := range records[1:] {
		if row[index["Language"]] == string(model.LangPython) {
			pythonRow = row
		}
	}
	if pythonRow == nil {
		t.Fatal("expected a row for python")
	}
	if pythonRow[index["Configured"]] != "true" || pythonRow[index["Succeeded"]] != "false" {
		t.Errorf("python row should be configured but not succeeded, got %v", pythonRow)
	}
	if pythonRow[index["Job conclusion"]] != "failure" {
		t.Errorf("python job conclusion = %q, want failure", pythonRow[index["Job conclusion"]])
	}
}

func TestWriteTableHighlightsProblems(t *testing.T) {
	var buffer bytes.Buffer
	err := WriteTable(&buffer, sampleReport(), TableOptions{
		IsTerminal: false,
		Width:      200,
		Properties: []string{"application"},
		Detailed:   true,
	})
	if err != nil {
		t.Fatalf("WriteTable returned an error: %v", err)
	}

	rendered := buffer.String()
	for _, expected := range []string{
		"acme/payments",
		"degraded",
		"not analyzed: python",
		"2 repositories, 1 needing attention",
		"By application",
	} {
		if !strings.Contains(rendered, expected) {
			t.Errorf("table output is missing %q\n---\n%s", expected, rendered)
		}
	}
}

func TestWriteTableHandlesEmptyResults(t *testing.T) {
	report := sampleReport()
	report.Repositories = nil
	report.Summary = model.BuildSummary(nil, "")

	var buffer bytes.Buffer
	if err := WriteTable(&buffer, report, TableOptions{Width: 120}); err != nil {
		t.Fatalf("WriteTable returned an error: %v", err)
	}
	if !strings.Contains(buffer.String(), "No repositories matched") {
		t.Errorf("empty results must be explained, got:\n%s", buffer.String())
	}
}

func TestPropertyColumnsAreSortedAndUnique(t *testing.T) {
	report := sampleReport()
	report.Repositories[0].Properties["tier"] = "1"

	columns := PropertyColumns(report)
	if len(columns) != 2 || columns[0] != "application" || columns[1] != "tier" {
		t.Fatalf("PropertyColumns = %v, want [application tier]", columns)
	}
}
