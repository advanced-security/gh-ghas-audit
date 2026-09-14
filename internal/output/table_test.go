package output

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/fatih/color"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
)

type failAtWrite struct {
	calls  int
	failAt int
	err    error
}

func (writer *failAtWrite) Write(data []byte) (int, error) {
	writer.calls++
	if writer.calls == writer.failAt {
		return 0, writer.err
	}
	return len(data), nil
}

func TestWriteTablePropagatesEveryWriteError(t *testing.T) {
	for _, name := range []string{"populated", "empty", "large-body"} {
		t.Run(name, func(t *testing.T) {
			report := sampleReport()
			report.Settings.StaleAfterInactive = "30d"
			report.Warnings = []string{"first warning", "second warning"}
			report.Stats.Incomplete = true
			report.Stats.RateLimitRemains = 123
			if name == "empty" {
				report.Repositories = nil
				report.Summary = model.BuildSummary(nil, "")
			} else {
				for len(report.Summary.Groups) < 16 {
					report.Summary.Groups = append(report.Summary.Groups, report.Summary.Groups[0])
				}
			}
			if name == "large-body" {
				report.Repositories[0].FullName = "acme/" + strings.Repeat("repository", 1000)
			}

			for _, terminal := range []bool{false, true} {
				t.Run(fmt.Sprintf("terminal=%t", terminal), func(t *testing.T) {
					opts := TableOptions{IsTerminal: terminal, Width: 200, Detailed: true}
					counter := &failAtWrite{}
					if err := WriteTable(counter, report, opts); err != nil {
						t.Fatal(err)
					}

					// Fail just one write, then allow later writes to succeed so
					// checking only the final write cannot hide an earlier error.
					want := errors.New("output failed")
					for failAt := 1; failAt <= counter.calls; failAt++ {
						t.Run(fmt.Sprintf("write-%d", failAt), func(t *testing.T) {
							writer := &failAtWrite{failAt: failAt, err: want}
							if err := WriteTable(writer, report, opts); !errors.Is(err, want) {
								t.Fatalf("write %d: got %v, want %v", failAt, err, want)
							}
						})
					}
				})
			}
		})
	}
}

func TestDetailedTableIncludesAllDiagnosticSources(t *testing.T) {
	report := sampleReport()
	repo := &report.Repositories[0]
	repo.Status.Reasons = []string{"scanning needs attention"}
	repo.Diagnostics = []model.Diagnostic{
		{Source: model.SourceAPI, Code: "analysis-error", Message: "analysis failed: compilation error"},
		{Source: model.SourceAPI, Code: "workflow-disabled", Message: "CodeQL workflow is disabled"},
		{Source: model.SourceLog, Code: "log-warning", Message: "no source code was extracted"},
		{Source: model.SourceAPI, Code: "analysis-error", Message: "analysis failed: compilation error"},
		{Source: model.SourceAPI, Code: "summary", Message: "scanning needs attention"},
	}
	repo.Errors = []string{"run jobs: HTTP 403"}
	want := "scanning needs attention; analysis failed: compilation error; CodeQL workflow is disabled; no source code was extracted (from logs); run jobs: HTTP 403"
	if got := detailCell(*repo); got != want {
		t.Fatalf("detail cell = %q, want %q", got, want)
	}
	var buffer bytes.Buffer
	if err := WriteTable(&buffer, report, TableOptions{Width: 200, Detailed: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buffer.String(), want) {
		t.Fatalf("detailed table lost diagnostic evidence:\n%s", buffer.String())
	}
}

func TestWriteTableRespectsTerminalColors(t *testing.T) {
	original := color.NoColor
	color.NoColor = false
	t.Cleanup(func() { color.NoColor = original })

	report := sampleReport()
	for _, severity := range model.AllSeverities() {
		report.Summary.BySeverity[string(severity)] = 1
	}
	report.Warnings = []string{"example warning"}
	report.Stats.Incomplete = true

	for _, terminal := range []bool{false, true} {
		t.Run(fmt.Sprintf("terminal=%t", terminal), func(t *testing.T) {
			var buffer bytes.Buffer
			if err := WriteTable(&buffer, report, TableOptions{IsTerminal: terminal, Width: 200}); err != nil {
				t.Fatal(err)
			}
			if colored := strings.Contains(buffer.String(), "\x1b["); colored != terminal {
				t.Errorf("ANSI colors present = %t, want %t:\n%s", colored, terminal, buffer.String())
			}
		})
	}
}

func TestLastScanCellPreservesUnknownFreshness(t *testing.T) {
	for _, test := range []struct {
		freshness model.FreshnessStatus
		want      string
	}{
		{model.FreshUnknown, "unknown"},
		{model.FreshNever, "never"},
		{model.FreshNotEvaluated, "-"},
		{model.FreshNotApplicable, "-"},
	} {
		repo := model.Repo{
			Status: model.Status{
				Configuration: model.ConfigConfigured,
				Freshness:     test.freshness,
			},
		}
		if got := lastScanCell(repo); got != test.want {
			t.Errorf("freshness %s rendered as %q, want %q", test.freshness, got, test.want)
		}
	}
}

func TestResolvePropertyColumnsUsesOrganizationSpelling(t *testing.T) {
	report := &model.Report{Repositories: []model.Repo{
		{Properties: map[string]string{"Project": "A", "Service Tier": "1"}},
	}}
	got := ResolvePropertyColumns(report, []string{"project", "SERVICE TIER", "Missing", "PROJECT"})
	want := []string{"Project", "Service Tier", "Missing"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolved columns = %v, want %v", got, want)
	}
}
