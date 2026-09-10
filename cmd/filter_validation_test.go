package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestInvalidScopeFiltersFailBeforeCollection(t *testing.T) {
	for _, test := range []struct{ flag, value string }{
		{"--visibility", "privte"},
		{"--visibility", "public,privte"},
		{"--visibility", "*"},
		{"--match", "["},
		{"--exclude", "service-["},
		{"--property-filter", "Project=["},
		{"--property-filter", "Project=service-["},
	} {
		t.Run(test.flag+"/"+test.value, func(t *testing.T) {
			root := newRootCommand()
			root.SetOut(&bytes.Buffer{})
			root.SetErr(&bytes.Buffer{})
			root.SetArgs([]string{
				"code-scanning", "--repository", "acme/repo", test.flag, test.value,
				"--cache-max-age", "invalid",
			})
			if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "invalid "+test.flag) {
				t.Fatalf("malformed filter was not rejected: %v", err)
			}
		})
	}
}

func TestValidScopeFiltersReachScopeValidation(t *testing.T) {
	for _, args := range [][]string{
		{"--visibility", "PUBLIC,private,internal"},
		{"--match", "*-api,[ab]*"},
		{"--exclude", "TEST-??"},
		{"--property-filter", "Project=service-*", "--property-filter", "Project=[ab]?"},
	} {
		root := newRootCommand()
		root.SetOut(&bytes.Buffer{})
		root.SetErr(&bytes.Buffer{})
		root.SetArgs(append([]string{"code-scanning"}, args...))
		if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "specify --organization") {
			t.Fatalf("valid filter %v failed: %v", args, err)
		}
	}
}

func TestParsePropertyFiltersValidatesEveryValue(t *testing.T) {
	for _, values := range [][]string{
		{"Project=["},
		{"Project=service-*,["},
		{"Project=service-*", "Project=["},
	} {
		if _, err := parsePropertyFilters(values); err == nil || !strings.Contains(err.Error(), "invalid --property-filter pattern") {
			t.Errorf("parsePropertyFilters(%q) must reject malformed patterns, got %v", values, err)
		}
	}

	filters, err := parsePropertyFilters([]string{"Project= service-*, web-? ", "Project=[ab]*", "Tier=1,2"})
	want := map[string][]string{
		"Project": {"service-*", "web-?", "[ab]*"},
		"Tier":    {"1", "2"},
	}
	if err != nil || !reflect.DeepEqual(filters, want) {
		t.Fatalf("valid multi-select filters = %v, %v; want %v", filters, err, want)
	}
}

func TestRepositoryScopeConflictsFailBeforeCacheAndCollection(t *testing.T) {
	for _, scope := range []struct{ flag, value string }{
		{"--organization", "acme"},
		{"--organizations", "acme,other"},
		{"--enterprise", "enterprise"},
	} {
		t.Run(scope.flag, func(t *testing.T) {
			for _, beforeCommand := range []bool{false, true} {
				// The invalid cache duration prevents any network work if scope
				// validation regresses, while identifying validation that ran late.
				cacheDir := filepath.Join(t.TempDir(), "cache")
				args := []string{"code-scanning", "--repository", "acme/repo"}
				if beforeCommand {
					args = []string{"--repository", "acme/repo", "code-scanning"}
				}
				args = append(args, scope.flag, scope.value, "--cache-dir", cacheDir, "--cache-max-age", "invalid", "--refresh")
				root := newRootCommand()
				root.SetOut(&bytes.Buffer{})
				root.SetErr(&bytes.Buffer{})
				root.SetArgs(args)
				if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "--repository cannot be combined") {
					t.Errorf("%v must fail scope validation before cache work, got %v", args, err)
				}
				if _, err := os.Stat(cacheDir); !os.IsNotExist(err) {
					t.Errorf("invalid scopes must not create the cache, got %v", err)
				}
			}
		})
	}
}

func TestOrganizationAndEnterpriseScopesStillReachCacheValidation(t *testing.T) {
	root := newRootCommand()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{
		"code-scanning", "--organization", "acme", "--enterprise", "enterprise",
		"--cache-max-age", "invalid",
	})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "invalid --cache-max-age") {
		t.Fatalf("organization and enterprise scopes must remain compatible, got %v", err)
	}
}
