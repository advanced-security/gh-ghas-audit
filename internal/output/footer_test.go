package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
)

// A scan in which every organization failed produces no repositories. If the
// table stops at "no repositories matched" it looks identical to a healthy
// estate that simply had nothing to report, which is the difference between
// "nothing is wrong" and "nothing was checked".
func TestEmptyTableStillReportsWarnings(t *testing.T) {
	report := &model.Report{
		Warnings: []string{"organization acme could not be read: 403 Forbidden"},
		Stats:    model.Stats{Incomplete: true},
	}

	var buffer bytes.Buffer
	if err := WriteTable(&buffer, report, TableOptions{Width: 200}); err != nil {
		t.Fatalf("WriteTable returned an error: %v", err)
	}

	out := buffer.String()
	if !strings.Contains(out, "could not be read") {
		t.Errorf("an empty table must still surface warnings, got:\n%s", out)
	}
	if !strings.Contains(out, "incomplete") {
		t.Errorf("an empty table must still surface the incomplete notice, got:\n%s", out)
	}
}

// Property names are matched case-insensitively, so two spellings of the same
// property must not become two columns filled with identical values.
func TestPropertyColumnsFoldCase(t *testing.T) {
	report := &model.Report{
		Repositories: []model.Repo{
			{Name: "one", Properties: map[string]string{"Project": "WUPH"}},
			{Name: "two", Properties: map[string]string{"project": "WUPH"}},
			{Name: "three", Properties: map[string]string{"PROJECT": "WUPH"}},
		},
	}

	columns := PropertyColumns(report)
	if len(columns) != 1 {
		t.Fatalf("property columns = %v, want a single folded column", columns)
	}
}

// Distinct properties are still distinct columns.
func TestPropertyColumnsKeepDistinctNames(t *testing.T) {
	report := &model.Report{
		Repositories: []model.Repo{
			{Name: "one", Properties: map[string]string{"Project": "WUPH", "tier": "1"}},
		},
	}

	if columns := PropertyColumns(report); len(columns) != 2 {
		t.Fatalf("property columns = %v, want two", columns)
	}
}
