package cmd

import (
	"bytes"
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
	} {
		t.Run(test.flag+"/"+test.value, func(t *testing.T) {
			root := newRootCommand()
			root.SetOut(&bytes.Buffer{})
			root.SetErr(&bytes.Buffer{})
			root.SetArgs([]string{"code-scanning", test.flag, test.value})
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
