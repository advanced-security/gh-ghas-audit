package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
	"github.com/advanced-security/gh-ghas-audit/v2/internal/output"
)

func TestDependabotCommandFlagsDefaults(t *testing.T) {
	root := newRootCommand()
	cmd, _, err := root.Find([]string{"dependabot"})
	if err != nil || cmd == root || cmd.RunE == nil {
		t.Fatalf("dependabot must execute the collector directly: %v", err)
	}
	for flag, want := range map[string]string{
		"scan-depth": "health", "concurrency": "8", "format": "table",
		"dependency-review-check-pattern": "dependency review",
	} {
		got := cmd.Flags().Lookup(flag)
		if got == nil || got.DefValue != want {
			t.Errorf("flag %s = %v, want default %q", flag, got, want)
		}
	}
}

func TestDependabotCommandRejectsRepositoryScopeConflicts(t *testing.T) {
	for _, scope := range []struct{ flag, value string }{
		{"--organization", "acme"},
		{"--organizations", "acme,other"},
		{"--enterprise", "enterprise"},
	} {
		root := newRootCommand()
		root.SetOut(&bytes.Buffer{})
		root.SetErr(&bytes.Buffer{})
		root.SetArgs([]string{"dependabot", "--repository", "acme/repo", scope.flag, scope.value})
		if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "--repository cannot be combined") {
			t.Errorf("%v must fail scope validation, got %v", scope, err)
		}
	}
}

func TestDependabotCommandRequiresScope(t *testing.T) {
	root := newRootCommand()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"dependabot"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "specify --organization") {
		t.Fatalf("missing scope should be rejected before collection, got %v", err)
	}
}

func TestDependabotCommandRejectsInvalidFormat(t *testing.T) {
	root := newRootCommand()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"dependabot", "-o", "acme", "--format", "invalid"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "unsupported format") {
		t.Fatalf("invalid format should be rejected before collection, got %v", err)
	}
}

func TestDependabotCommandRejectsLanguageCSVFormat(t *testing.T) {
	root := newRootCommand()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"dependabot", "-o", "acme", "--format", "language-csv"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "language-csv is not supported") {
		t.Fatalf("language-csv should be rejected for dependabot, got %v", err)
	}
}

// TestDependabotCommandRejectsSecurityConfiguration verifies that
// --security-configuration, which code-scanning supports to scope a scan to
// a single security configuration, is explicitly rejected for dependabot
// rather than silently ignored. The dependabot collector has no filtering
// mechanism for it at all (unlike --format language-csv, which is rejected
// for the same "not supported, so fail loudly" reason), so accepting the
// flag without effect would silently produce an unscoped, misleading scan.
func TestDependabotCommandRejectsSecurityConfiguration(t *testing.T) {
	root := newRootCommand()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"dependabot", "-o", "acme", "--security-configuration", "default"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "--security-configuration is not supported") {
		t.Fatalf("--security-configuration should be rejected for dependabot, got %v", err)
	}
}

func TestDependabotCommandRejectsInvalidConcurrency(t *testing.T) {
	root := newRootCommand()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"dependabot", "-o", "acme", "--concurrency", "0"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "must be at least 1") {
		t.Fatalf("invalid --concurrency should be rejected before collection, got %v", err)
	}
}

func TestDependabotOptionsWriteReportUsesCommandWriter(t *testing.T) {
	var stdout bytes.Buffer
	cmd := newDependabotCommand(&scopeOptions{})
	cmd.SetOut(&stdout)
	opts := &dependabotOptions{}
	report := &model.DependabotReport{
		SchemaVersion: model.DependabotSchemaVersion,
		Settings:      model.DependabotSettings{ScanDepth: "config"},
	}
	if err := opts.writeReport(cmd, report, output.FormatJSON); err != nil {
		t.Fatal(err)
	}
	var got model.DependabotReport
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil || got.Settings.ScanDepth != "config" {
		t.Fatalf("report lost depth or JSON shape: %s (%v)", stdout.String(), err)
	}
}

func TestMatchedDependabotSeveritiesDeduplicates(t *testing.T) {
	report := &model.DependabotReport{
		Repositories: []model.DependabotRepo{
			{Status: model.DependabotStatus{Overall: model.SeverityFailing}},
			{Status: model.DependabotStatus{Overall: model.SeverityFailing}},
			{Status: model.DependabotStatus{Overall: model.SeverityHealthy}},
		},
	}
	matched := matchedDependabotSeverities(report, []model.Severity{model.SeverityFailing, model.SeverityStalled})
	if len(matched) != 1 || matched[0] != string(model.SeverityFailing) {
		t.Fatalf("matched severities = %v, want [failing]", matched)
	}
	if matchedDependabotSeverities(report, nil) != nil {
		t.Fatal("no --fail-on values should match nothing")
	}
}

func TestApplyDependabotFiltersRecomputesSummary(t *testing.T) {
	report := &model.DependabotReport{
		Repositories: []model.DependabotRepo{
			{Organization: "acme", Name: "a", Status: model.DependabotStatus{Overall: model.SeverityFailing}},
			{Organization: "acme", Name: "b", Status: model.DependabotStatus{Overall: model.SeverityHealthy}},
		},
		Organizations: []model.OrgReport{{Login: "unreadable", Error: "403"}},
	}
	applyDependabotFilters(report, []model.Severity{model.SeverityFailing})

	if len(report.Repositories) != 1 || report.Repositories[0].Name != "a" {
		t.Fatalf("filtered repositories = %v, want only [a]", report.Repositories)
	}
	if report.Summary.TotalRepositories != 1 {
		t.Fatalf("summary total = %d, want 1", report.Summary.TotalRepositories)
	}

	foundUnreadable := false
	for _, org := range report.Organizations {
		if org.Login == "unreadable" && org.Error == "403" {
			foundUnreadable = true
		}
	}
	if !foundUnreadable {
		t.Fatalf("organization-level scan errors must survive filtering, got %v", report.Organizations)
	}
}

// TestMergeDependabotOrgErrorsSortsAppendedEntries verifies that when
// multiple organizations' repositories are entirely filtered out, their
// re-appended error entries come back in a deterministic (alphabetical by
// login), not map-iteration-order-dependent, sequence — this is
// user-facing table/json/csv output, so its ordering must be stable across
// runs with identical input.
func TestMergeDependabotOrgErrorsSortsAppendedEntries(t *testing.T) {
	previous := []model.OrgReport{
		{Login: "zeta", Error: "403"},
		{Login: "mid", Error: "500"},
		{Login: "alpha", Error: "403"},
	}
	for attempt := 0; attempt < 20; attempt++ {
		merged := mergeDependabotOrgErrors(nil, previous)
		if len(merged) != 3 {
			t.Fatalf("merged = %v, want 3 entries", merged)
		}
		if merged[0].Login != "alpha" || merged[1].Login != "mid" || merged[2].Login != "zeta" {
			t.Fatalf("attempt %d: merged order = [%s, %s, %s], want [alpha, mid, zeta]",
				attempt, merged[0].Login, merged[1].Login, merged[2].Login)
		}
	}
}
