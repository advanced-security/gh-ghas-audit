package output

import (
	"bytes"
	"encoding/csv"
	"testing"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
)

func TestLanguageCSVDoesNotInventConfigRuntimeEvidence(t *testing.T) {
	for _, test := range []struct {
		depth     string
		execution model.ExecutionStatus
		want      string
	}{
		{"config", model.ExecNotEvaluated, ""},
		{"config", "", ""},
		{"", model.ExecNotEvaluated, ""},
		{"health", model.ExecFailure, "false"},
		{"diagnostics", model.ExecFailure, "false"},
	} {
		report := &model.Report{
			Settings: model.Settings{ScanDepth: test.depth},
			Repositories: []model.Repo{{
				Name: "repo", Organization: "org",
				Status: model.Status{Execution: test.execution},
				Languages: []model.LanguageState{{
					Language: model.LangGo, Detected: true, Configured: true,
				}},
			}},
		}
		var buffer bytes.Buffer
		if err := WriteLanguageCSV(&buffer, report, nil); err != nil {
			t.Fatal(err)
		}
		rows, err := csv.NewReader(&buffer).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		values := map[string]string{}
		for index, column := range rows[0] {
			values[column] = rows[1][index]
		}
		if values["Analyzed"] != test.want || values["Succeeded"] != test.want {
			t.Errorf("%s/%s: unmeasured runtime became false: %v", test.depth, test.execution, values)
		}
		if values["Detected"] != "true" || values["Configured"] != "true" || values["Evidence complete"] != "true" {
			t.Errorf("configuration evidence was lost: %v", values)
		}
	}
}
