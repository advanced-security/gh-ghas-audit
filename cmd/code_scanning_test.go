package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/collector"
	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
	"github.com/advanced-security/gh-ghas-audit/v2/internal/output"
	"github.com/spf13/cobra"
)

func TestUnifiedCommand(t *testing.T) {
	root := newRootCommand()
	cmd, _, err := root.Find([]string{"code-scanning"})
	if err != nil || cmd == root || cmd.RunE == nil {
		t.Fatalf("code-scanning must execute the collector directly: %v", err)
	}
	if cmd.HasSubCommands() {
		t.Fatal("code-scanning must not retain a status subcommand")
	}
	for flag, want := range map[string]string{
		"scan-depth": "health", "deep-scope": "all", "concurrency": "8", "format": "table",
	} {
		got := cmd.Flags().Lookup(flag)
		if got == nil || got.DefValue != want {
			t.Errorf("flag %s = %v, want default %q", flag, got, want)
		}
	}
}

func TestUnifiedCommandRejectsLegacySyntaxBeforeCollection(t *testing.T) {
	for _, args := range [][]string{
		{"code-scanning", "status", "-o", "org"},
		{"code-scanning", "-o", "org", "--csv-output", "old.csv"},
		{"--csv-output", "old.csv", "code-scanning", "-o", "org"},
	} {
		root := newRootCommand()
		root.SetOut(&bytes.Buffer{})
		root.SetErr(&bytes.Buffer{})
		root.SetArgs(args)
		if err := root.Execute(); err == nil || (!strings.Contains(err.Error(), "unknown") && !strings.Contains(err.Error(), "accepts")) {
			t.Errorf("%v should fail at argument parsing, got %v", args, err)
		}
	}
}

func TestCommandFlagsAreIsolated(t *testing.T) {
	first := newRootCommand()
	cmd, _, _ := first.Find([]string{"code-scanning"})
	if err := cmd.Flags().Set("scan-depth", "diagnostics"); err != nil {
		t.Fatal(err)
	}
	second := newRootCommand()
	fresh, _, _ := second.Find([]string{"code-scanning"})
	if got, _ := fresh.Flags().GetString("scan-depth"); got != "health" {
		t.Fatalf("a previous command leaked its depth: %q", got)
	}
}

func TestScopeFlagsWorkBeforeOrAfterCommand(t *testing.T) {
	for _, args := range [][]string{
		{"--organization", "org", "code-scanning", "--format", "invalid"},
		{"code-scanning", "--organizations", "org", "--format", "invalid"},
		{"code-scanning", "--enterprise", "enterprise", "--scan-depth", "config", "--format", "invalid"},
		{"code-scanning", "-r", "owner/repo", "--format", "invalid"},
	} {
		root := newRootCommand()
		root.SetOut(&bytes.Buffer{})
		root.SetErr(&bytes.Buffer{})
		root.SetArgs(args)
		if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "unsupported format") {
			t.Errorf("%v did not reach the unified handler: %v", args, err)
		}
	}
}

func TestVersionUsesReleaseOverride(t *testing.T) {
	previous := buildVersion
	t.Cleanup(func() { buildVersion = previous })
	buildVersion = "v2.0.0"
	for _, args := range [][]string{{"version"}, {"--version"}} {
		root := newRootCommand()
		var buffer bytes.Buffer
		root.SetOut(&buffer)
		root.SetArgs(args)
		if err := root.Execute(); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buffer.String(), "v2.0.0") {
			t.Fatalf("release version absent from %v: %q", args, buffer.String())
		}
	}
}

func TestUnifiedCommandRejectsInvalidLimits(t *testing.T) {
	for _, flag := range []string{"--concurrency", "--deep-diagnostics-max-repos", "--deep-diagnostics-max-mb"} {
		root := newRootCommand()
		root.SetOut(&bytes.Buffer{})
		root.SetErr(&bytes.Buffer{})
		root.SetArgs([]string{"code-scanning", "-o", "org", flag, "0"})
		if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "must be at least 1") {
			t.Fatalf("invalid %s reached collection: %v", flag, err)
		}
	}
}

func TestReportUsesCommandWriterOrOutputFile(t *testing.T) {
	for _, toFile := range []bool{false, true} {
		var stdout bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetOut(&stdout)
		opts := &codeScanningOptions{}
		if toFile {
			opts.outputPath = filepath.Join(t.TempDir(), "report.json")
		}
		report := &model.Report{SchemaVersion: model.SchemaVersion, Settings: model.Settings{ScanDepth: "config"}}
		if err := opts.writeReport(cmd, report, output.FormatJSON); err != nil {
			t.Fatal(err)
		}
		data := stdout.Bytes()
		if toFile {
			if stdout.Len() != 0 {
				t.Fatal("--output also wrote to stdout")
			}
			var err error
			data, err = os.ReadFile(opts.outputPath)
			if err != nil {
				t.Fatal(err)
			}
		}
		var got model.Report
		if err := json.Unmarshal(data, &got); err != nil || got.Settings.ScanDepth != "config" {
			t.Fatalf("report lost depth or JSON shape: %s (%v)", data, err)
		}
	}
}

type failedWriter struct{ err error }

func (w failedWriter) Write([]byte) (int, error) { return 0, w.err }

func TestReportPropagatesWriteErrors(t *testing.T) {
	failure := errors.New("writer failed")
	cmd := &cobra.Command{}
	cmd.SetOut(failedWriter{failure})
	opts := &codeScanningOptions{}
	if err := opts.writeReport(cmd, &model.Report{}, output.FormatJSON); !errors.Is(err, failure) {
		t.Fatalf("write error was swallowed: %v", err)
	}
}

func TestResolveDepth(t *testing.T) {
	cases := []struct {
		name       string
		depth      string
		scope      string
		legacy     string
		explicit   bool
		wantDepth  collector.Depth
		wantScope  collector.DeepDiagnosticsMode
		wantErrHas string
	}{
		{
			name:      "default is health with no log inspection",
			depth:     "health",
			scope:     "all",
			wantDepth: collector.DepthHealth,
			wantScope: collector.DeepDiagnosticsOff,
		},
		{
			name:      "config gathers no runtime evidence",
			depth:     "config",
			scope:     "all",
			explicit:  true,
			wantDepth: collector.DepthConfig,
			wantScope: collector.DeepDiagnosticsOff,
		},
		{
			// Restricting inspection to repositories that already look
			// unhealthy can only explain a failure, never discover one, so it
			// must not be the default.
			name:      "diagnostics inspects every repository by default",
			depth:     "diagnostics",
			scope:     "all",
			explicit:  true,
			wantDepth: collector.DepthDiagnostics,
			wantScope: collector.DeepDiagnosticsAll,
		},
		{
			name:      "diagnostics scope can be narrowed deliberately",
			depth:     "diagnostics",
			scope:     "problematic",
			explicit:  true,
			wantDepth: collector.DepthDiagnostics,
			wantScope: collector.DeepDiagnosticsProblematic,
		},
		{
			name:      "an empty scope still inspects everything",
			depth:     "diagnostics",
			scope:     "",
			explicit:  true,
			wantDepth: collector.DepthDiagnostics,
			wantScope: collector.DeepDiagnosticsAll,
		},
		{
			name:      "dial words are accepted as aliases",
			depth:     "high",
			scope:     "all",
			explicit:  true,
			wantDepth: collector.DepthDiagnostics,
			wantScope: collector.DeepDiagnosticsAll,
		},
		{
			name:      "medium maps to health",
			depth:     "medium",
			scope:     "all",
			explicit:  true,
			wantDepth: collector.DepthHealth,
			wantScope: collector.DeepDiagnosticsOff,
		},
		{
			name:      "low maps to config",
			depth:     "low",
			scope:     "all",
			explicit:  true,
			wantDepth: collector.DepthConfig,
			wantScope: collector.DeepDiagnosticsOff,
		},
		{
			// The deprecated flag keeps working on its own.
			name:      "deprecated flag still selects diagnostics",
			depth:     "health",
			scope:     "all",
			legacy:    "problematic",
			wantDepth: collector.DepthDiagnostics,
			wantScope: collector.DeepDiagnosticsProblematic,
		},
		{
			// Silently choosing the expensive option would be the wrong way to
			// resolve a contradiction.
			name:       "deprecated flag conflicting with an explicit depth is rejected",
			depth:      "config",
			scope:      "all",
			legacy:     "all",
			explicit:   true,
			wantErrHas: "conflicts with --scan-depth config",
		},
		{
			name:       "an unknown depth is rejected",
			depth:      "deepest",
			scope:      "all",
			explicit:   true,
			wantErrHas: "invalid --scan-depth",
		},
		{
			name:       "an unknown scope is rejected",
			depth:      "diagnostics",
			scope:      "some",
			explicit:   true,
			wantErrHas: "invalid --deep-scope",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			depth, scope, err := resolveDepth(test.depth, test.scope, test.legacy, test.explicit)

			if test.wantErrHas != "" {
				if err == nil {
					t.Fatalf("expected an error containing %q, got none", test.wantErrHas)
				}
				if !strings.Contains(err.Error(), test.wantErrHas) {
					t.Fatalf("error = %q, want it to contain %q", err, test.wantErrHas)
				}
				return
			}

			if err != nil {
				t.Fatalf("resolveDepth returned an error: %v", err)
			}
			if depth != test.wantDepth {
				t.Errorf("depth = %q, want %q", depth, test.wantDepth)
			}
			if scope != test.wantScope {
				t.Errorf("scope = %q, want %q", scope, test.wantScope)
			}
		})
	}
}
