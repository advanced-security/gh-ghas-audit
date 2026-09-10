package collector

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/ghapi"
	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
)

type pagedJobsClient struct {
	*fakeClient
	pages     []jobList
	pageError error
	paginated bool
}

func (c *pagedJobsClient) GetPaginatedJSON(ctx context.Context, path string, collect func([]byte) error) error {
	if !strings.Contains(path, "/jobs?") {
		return c.fakeClient.GetPaginatedJSON(ctx, path, collect)
	}
	c.paginated = true
	for _, page := range c.pages {
		data, err := json.Marshal(page)
		if err != nil {
			return err
		}
		if err := collect(data); err != nil {
			return err
		}
	}
	return c.pageError
}

func TestAllAdvancedJobPagesAreRequiredForCoverage(t *testing.T) {
	for _, pageError := range []error{nil, errors.New("second page failed"), &ghapi.StatusError{StatusCode: 404}} {
		first := jobsFor(map[string]string{"go": "success"})
		for len(first.Jobs) < 100 {
			first.Jobs = append(first.Jobs, first.Jobs[0])
		}
		first.TotalCount = 101
		second := jobsFor(map[string]string{"java-kotlin": "failure"})
		client := buildClient(t, scenario{
			name: "matrix", languages: []string{"Go", "Java"},
			defaultSetup: defaultSetup{State: "not-configured"},
			workflows:    advancedWorkflows(".github/workflows/codeql.yml"),
			runs:         map[string]any{"": runListFor(".github/workflows/codeql.yml", "success", time.Hour)},
			jobs:         first,
		})
		recent := time.Now().Add(-time.Hour)
		client.set("repos/"+testOrg+"/matrix/code-scanning/analyses", []codeScanningAnalysis{
			{AnalysisKey: ".github/workflows/codeql.yml:analyze", Category: "/language:go", CreatedAt: &recent},
			{AnalysisKey: ".github/workflows/codeql.yml:analyze", Category: "/language:java-kotlin", CreatedAt: &recent},
		})
		pages := []jobList{first, second}
		if pageError != nil {
			pages = pages[:1]
		}
		paged := &pagedJobsClient{fakeClient: client, pages: pages, pageError: pageError}
		options := defaultActivityOptions()
		options.Organizations = []string{testOrg}
		report, err := New(paged, options).Collect(context.Background(), "test")
		if err != nil {
			t.Fatal(err)
		}
		repo := findRepo(t, report, "matrix")
		if !paged.paginated {
			t.Fatal("job collection did not request paginated evidence")
		}
		if repo.Status.Overall == model.SeverityHealthy {
			t.Fatal("later-page failures or missing evidence were masked by old analyses")
		}
		if pageError != nil {
			if !repo.Status.Incomplete || !report.Stats.Incomplete || len(repo.SucceededLanguages) != 0 {
				t.Fatalf("partial pagination became complete evidence: %+v", repo)
			}
		} else if !containsLanguage(repo.FailedLanguages, model.LangJavaKotlin) || repo.Status.Incomplete {
			t.Fatalf("Java failure on the second page was not preserved: %+v", repo)
		}
	}
}

func TestPermissionDeniedCodeScanningEvidenceIsIncomplete(t *testing.T) {
	for _, endpoint := range []string{"default-setup", "codeql/databases"} {
		client := buildClient(t, scenario{
			name: "restricted", languages: []string{"Go"},
			defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
			workflows:    codeqlWorkflows(),
			runs:         map[string]any{"": runList("success", time.Hour)},
			jobs:         jobsFor(map[string]string{"go": "success"}),
			databases:    databasesFor([]string{"go"}, time.Hour),
		})
		client.set("repos/"+testOrg+"/restricted/code-scanning/"+endpoint,
			&ghapi.StatusError{StatusCode: 403, Message: "Resource not accessible by integration"})
		report := collect(t, client, defaultActivityOptions())
		repo := findRepo(t, report, "restricted")
		if !repo.Status.Incomplete || !report.Stats.Incomplete || len(repo.Errors) == 0 {
			t.Errorf("%s permission failure looked complete: %+v", endpoint, repo.Status)
		}
		if repo.Status.Overall == model.SeverityHealthy {
			t.Errorf("%s permission failure was reported healthy", endpoint)
		}
	}
}
