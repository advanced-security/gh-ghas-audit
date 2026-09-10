package cmd

import (
	"strings"
	"testing"

	"github.com/advanced-security/gh-ghas-audit/internal/collector"
)

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
