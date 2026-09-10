package collector

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/diagnostics"
	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
	"github.com/advanced-security/gh-ghas-audit/v2/internal/output"
)

type cleanLogs struct{ archive []byte }

func (c cleanLogs) Host() string { return "github.com" }
func (c cleanLogs) GetBytesLimited(context.Context, string, int64) ([]byte, error) {
	return c.archive, nil
}

func TestDiagnosticsBudgetMarksSkippedRepositoryIncomplete(t *testing.T) {
	scenarios := make([]scenario, 2)
	for index, name := range []string{"one", "two"} {
		scenarios[index] = scenario{
			name: name, languages: []string{"Go"},
			defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
			workflows:    codeqlWorkflows(), runs: map[string]any{"": runList("success", time.Hour)},
			jobs:      jobsFor(map[string]string{"go": "success"}),
			databases: databasesFor([]string{"go"}, time.Hour),
		}
	}
	var archive bytes.Buffer
	if err := zip.NewWriter(&archive).Close(); err != nil {
		t.Fatal(err)
	}
	options := defaultActivityOptions()
	options.Depth = DepthDiagnostics
	options.DeepDiagnostics = DeepDiagnosticsAll
	options.Concurrency = 1
	options.LogFetcher = diagnostics.NewFetcher(cleanLogs{archive.Bytes()}, diagnostics.Limits{MaxRepositories: 1})
	report := collect(t, buildClient(t, scenarios...), options)
	if !report.Stats.Incomplete || report.Summary.BySeverity[string(model.SeverityHealthy)] != 1 {
		t.Fatalf("expected one healthy repo and an incomplete report: %+v", report.Summary)
	}
	var skipped *model.Repo
	for index := range report.Repositories {
		repo := &report.Repositories[index]
		if repo.Status.Incomplete {
			skipped = repo
		}
	}
	if skipped == nil || skipped.Status.Overall != model.SeverityUnknown ||
		len(skipped.Errors) != 1 || !strings.Contains(skipped.Errors[0], "budget") {
		t.Fatalf("skipped log inspection was hidden: %+v", skipped)
	}
	for _, write := range []func(*bytes.Buffer) error{
		func(b *bytes.Buffer) error { return output.WriteCSV(b, report, nil) },
		func(b *bytes.Buffer) error { return output.WriteLanguageCSV(b, report, nil) },
	} {
		var buffer bytes.Buffer
		if err := write(&buffer); err != nil {
			t.Fatal(err)
		}
		rows, err := csv.NewReader(&buffer).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		repositoryColumn, completeColumn := -1, -1
		for index, column := range rows[0] {
			if column == "Repository" {
				repositoryColumn = index
			}
			if column == "Evidence complete" {
				completeColumn = index
			}
		}
		if repositoryColumn < 0 || completeColumn < 0 {
			t.Fatal("missing CSV evidence headers")
		}
		found := false
		for _, row := range rows[1:] {
			if row[repositoryColumn] == skipped.Name {
				found = true
				if row[completeColumn] != "false" {
					t.Fatalf("skipped log evidence exported as complete: %v", row)
				}
			}
		}
		if !found {
			t.Fatal("skipped repository missing from CSV")
		}
	}
}
