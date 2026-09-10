package collector

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/ghapi"
	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
	"github.com/advanced-security/gh-ghas-audit/v2/internal/output"
)

func TestLanguageRuntimeEvaluationSurvivesCanonicalExports(t *testing.T) {
	for _, test := range []struct {
		name       string
		depth      Depth
		restricted bool
		want       model.RuntimeEvaluation
	}{
		{"config", DepthConfig, false, model.RuntimeNotEvaluated},
		{"health", DepthHealth, false, model.RuntimeEvaluated},
		{"incomplete", DepthHealth, true, model.RuntimeIncomplete},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := buildClient(t, scenario{
				name: "repo", languages: []string{"Go"},
				defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
				workflows:    codeqlWorkflows(),
				runs:         map[string]any{"": runList("success", time.Hour)},
				jobs:         jobsFor(map[string]string{"go": "success"}),
				databases:    databasesFor([]string{"go"}, time.Hour),
			})
			if test.restricted {
				client.set("repos/"+testOrg+"/repo/actions/runs/",
					&ghapi.StatusError{StatusCode: 403, Message: "denied"})
			}
			options := defaultActivityOptions()
			options.Depth = test.depth
			report := collect(t, client, options)
			data, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			var decoded model.Report
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			state := decoded.Repositories[0].Languages[0]
			if state.RuntimeEvaluation != test.want {
				t.Fatalf("runtime provenance lost: %+v", state)
			}
			for _, repo := range []model.Repo{report.Repositories[0], decoded.Repositories[0]} {
				record, err := json.Marshal(repo)
				if err != nil {
					t.Fatal(err)
				}
				var raw struct {
					Languages []map[string]any `json:"languages"`
				}
				if err := json.Unmarshal(record, &raw); err != nil {
					t.Fatal(err)
				}
				language := raw.Languages[0]
				if test.want == model.RuntimeNotEvaluated {
					if language["analyzed"] != nil || language["succeeded"] != nil {
						t.Fatalf("unmeasured runtime is not null: %s", record)
					}
				} else if language["analyzed"] == nil || language["succeeded"] == nil {
					t.Fatalf("evaluated runtime lost its boolean evidence: %s", record)
				}
			}
			var stream bytes.Buffer
			if err := output.WriteNDJSON(&stream, &decoded); err != nil {
				t.Fatal(err)
			}
			if test.want == model.RuntimeNotEvaluated && !bytes.Contains(stream.Bytes(), []byte(`"analyzed":null`)) {
				t.Fatalf("NDJSON lost null runtime values: %s", stream.Bytes())
			}
		})
	}
}
