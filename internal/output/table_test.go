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

// SARIF detail is per-language, but the table's DETAIL column is
// repository-scoped: it must condense every language into a single line
// rather than reproducing the full per-language breakdown that language-csv
// already exports.
func TestSarifSummaryCondensesPerLanguageDetail(t *testing.T) {
	rule := 3
	repo := model.Repo{
		Languages: []model.LanguageState{
			{Language: model.LangGo, SARIFCollected: true, RuleCount: &rule},
			{Language: model.LangPython, SARIFCollected: true, SARIFLanguageMismatch: true},
			{Language: model.LangJavaKotlin, SARIFError: "analysis SARIF is unavailable, likely expired"},
			// Never attempted: no SarifFetcher, or --deep-scope excluded it.
			{Language: model.LangCSharp},
		},
	}
	want := "SARIF 2/3 collected; language mismatch: python; SARIF error: java-kotlin"
	if got := sarifSummary(repo); got != want {
		t.Fatalf("sarifSummary = %q, want %q", got, want)
	}
	if got := detailCell(repo); !strings.Contains(got, want) {
		t.Fatalf("detail cell = %q, want it to contain %q", got, want)
	}
}

// A repository where SARIF was never attempted for any language (no
// SarifFetcher, or a scan depth below diagnostics) must not print a SARIF
// note at all.
func TestSarifSummaryIsEmptyWithoutAnyAttempt(t *testing.T) {
	repo := model.Repo{Languages: []model.LanguageState{{Language: model.LangGo}}}
	if got := sarifSummary(repo); got != "" {
		t.Fatalf("sarifSummary = %q, want empty when SARIF was never attempted", got)
	}
}

// Languages that share the same CodeQL CLI version are grouped into one
// entry so a reader is not left guessing whether "2.20.3" applies to every
// language; a differing version (a partial CLI upgrade) still stands out as
// its own tagged group.
func TestCodeqlVersionSummaryGroupsSharedVersionsAndTagsMismatches(t *testing.T) {
	states := []model.LanguageState{
		{Language: model.LangJavaKotlin, SARIFCollected: true, CodeQLVersion: "2.20.3"},
		{Language: model.LangCSharp, SARIFCollected: true, CodeQLVersion: "2.20.3"},
		{Language: model.LangPython, SARIFCollected: true, CodeQLVersion: "2.19.1"},
		// Never collected, so it must not contribute a stray empty group.
		{Language: model.LangGo},
	}
	want := "2.20.3[java-kotlin, csharp]; 2.19.1[python]"
	if got := codeqlVersionSummary(states); got != want {
		t.Fatalf("codeqlVersionSummary = %q, want %q", got, want)
	}
}

func TestCodeqlVersionSummaryIsEmptyWithoutAnyCollectedVersion(t *testing.T) {
	states := []model.LanguageState{{Language: model.LangGo}, {Language: model.LangPython, SARIFError: "budget exhausted"}}
	if got := codeqlVersionSummary(states); got != "" {
		t.Fatalf("codeqlVersionSummary = %q, want empty", got)
	}
}

// Query packs are tagged per language because, unlike a CodeQL version,
// packs are never expected to be shared across languages, and a mismatched
// SARIFLanguage must not be silently merged into the wrong language's list.
func TestQueryPacksSummaryTagsEveryPackWithItsLanguage(t *testing.T) {
	states := []model.LanguageState{
		{Language: model.LangJavaKotlin, SARIFCollected: true, QueryPacks: []string{"codeql/java-queries@1.2.3", "codeql/java-security-extended@1.2.3"}},
		{Language: model.LangPython, SARIFCollected: true, QueryPacks: []string{"codeql/python-queries@0.9.1"}},
		// Never collected, so its (absent) packs must not appear.
		{Language: model.LangGo, SARIFError: "analysis SARIF is unavailable"},
	}
	want := "codeql/java-queries@1.2.3[java-kotlin]; codeql/java-security-extended@1.2.3[java-kotlin]; codeql/python-queries@0.9.1[python]"
	if got := queryPacksSummary(states); got != want {
		t.Fatalf("queryPacksSummary = %q, want %q", got, want)
	}
}

func TestQueryPacksSummaryIsEmptyWithoutAnyCollectedPacks(t *testing.T) {
	states := []model.LanguageState{{Language: model.LangGo}}
	if got := queryPacksSummary(states); got != "" {
		t.Fatalf("queryPacksSummary = %q, want empty", got)
	}
}

// The table's new evidence columns must actually reach the rendered output,
// not just the helper functions in isolation.
func TestWriteTableIncludesCodeqlVersionAndQueryPacksColumns(t *testing.T) {
	report := sampleReport()
	repo := &report.Repositories[0]
	repo.Languages[0].SARIFCollected = true
	repo.Languages[0].CodeQLVersion = "2.20.3"
	repo.Languages[0].QueryPacks = []string{"codeql/java-queries@1.2.3"}

	var buffer bytes.Buffer
	if err := WriteTable(&buffer, report, TableOptions{Width: 200}); err != nil {
		t.Fatal(err)
	}
	output := buffer.String()
	if !strings.Contains(output, "CODEQL VERSION") || !strings.Contains(output, "QUERY PACKS") {
		t.Fatalf("table is missing the new evidence column headers:\n%s", output)
	}
	if !strings.Contains(output, "2.20.3[java-kotlin]") || !strings.Contains(output, "codeql/java-queries@1.2.3[java-kotlin]") {
		t.Fatalf("table did not render the new evidence columns:\n%s", output)
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
