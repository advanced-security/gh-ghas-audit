package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/advanced-security/gh-ghas-audit/internal/ghapi"
	"github.com/advanced-security/gh-ghas-audit/internal/model"
)

// fakeClient serves canned responses so collection and classification can be
// exercised without network access.
type fakeClient struct {
	responses map[string]any
	graphql   func(query string, variables map[string]any, out any) error
	stats     ghapi.Stats

	mu       sync.Mutex
	requests []string
	warned   map[string]bool
}

func newFakeClient() *fakeClient {
	return &fakeClient{responses: map[string]any{}, warned: map[string]bool{}}
}

func (f *fakeClient) Host() string        { return "github.com" }
func (f *fakeClient) Stats() *ghapi.Stats { return &f.stats }
func (f *fakeClient) WarnOnce(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.warned[key] {
		return false
	}
	f.warned[key] = true
	return true
}

// set registers a response for any request whose path starts with prefix.
func (f *fakeClient) set(prefix string, value any) {
	f.responses[prefix] = value
}

func (f *fakeClient) lookup(path string) (any, bool) {
	f.mu.Lock()
	f.requests = append(f.requests, path)
	f.mu.Unlock()

	var bestKey string
	var best any
	found := false
	for prefix, value := range f.responses {
		if strings.HasPrefix(path, prefix) && len(prefix) > len(bestKey) {
			bestKey, best, found = prefix, value, true
		}
	}
	return best, found
}

func (f *fakeClient) GetJSON(_ context.Context, path string, out any) error {
	value, ok := f.lookup(path)
	if !ok {
		return &ghapi.StatusError{StatusCode: http.StatusNotFound, URL: path, Message: "Not Found"}
	}
	if err, isErr := value.(error); isErr {
		return err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(encoded, out)
}

func (f *fakeClient) GetPaginatedJSON(_ context.Context, path string, collect func([]byte) error) error {
	value, ok := f.lookup(path)
	if !ok {
		return &ghapi.StatusError{StatusCode: http.StatusNotFound, URL: path, Message: "Not Found"}
	}
	if err, isErr := value.(error); isErr {
		return err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return collect(encoded)
}

func (f *fakeClient) GraphQL(_ context.Context, query string, variables map[string]any, out any) error {
	if f.graphql == nil {
		return fmt.Errorf("unexpected GraphQL query")
	}
	return f.graphql(query, variables, out)
}

func (f *fakeClient) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

// scenario describes one repository's API surface.
type scenario struct {
	name          string
	languages     []string
	defaultSetup  any
	workflows     any
	runs          map[string]any
	jobs          any
	databases     any
	attachment    string
	configuration string
	// pushedAt is how long ago the repository was last pushed to. Zero uses a
	// recent default.
	pushedAt time.Duration
	// noPushedAt omits push history entirely.
	noPushedAt bool
	// languagesHasNext marks the language connection as truncated, so the
	// collector falls back to REST.
	languagesHasNext bool
}

const testOrg = "test-org"

func buildClient(t *testing.T, scenarios ...scenario) *fakeClient {
	t.Helper()
	client := newFakeClient()

	nodes := make([]map[string]any, 0, len(scenarios))
	for _, item := range scenarios {
		languageNodes := make([]map[string]string, 0, len(item.languages))
		for _, language := range item.languages {
			languageNodes = append(languageNodes, map[string]string{"name": language})
		}

		pushAge := item.pushedAt
		if pushAge == 0 {
			pushAge = 24 * time.Hour
		}
		var pushedAt any
		if !item.noPushedAt {
			pushedAt = time.Now().Add(-pushAge).Format(time.RFC3339)
		}

		nodes = append(nodes, map[string]any{
			"name":             item.name,
			"url":              "https://github.com/" + testOrg + "/" + item.name,
			"isArchived":       false,
			"isFork":           false,
			"visibility":       "PRIVATE",
			"pushedAt":         pushedAt,
			"defaultBranchRef": map[string]string{"name": "main"},
			"languages": map[string]any{
				"nodes":    languageNodes,
				"pageInfo": map[string]any{"hasNextPage": item.languagesHasNext},
			},
		})
	}

	client.graphql = func(_ string, _ map[string]any, out any) error {
		payload := map[string]any{
			"organization": map[string]any{
				"repositories": map[string]any{
					"pageInfo": map[string]any{"hasNextPage": false, "endCursor": ""},
					"nodes":    nodes,
				},
			},
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		return json.Unmarshal(encoded, out)
	}

	// Organization level endpoints.
	client.set(fmt.Sprintf("orgs/%s/code-security/configurations?", testOrg), []securityConfiguration{
		{ID: 1, Name: "Production", TargetType: "organization"},
	})

	attachments := make([]configurationRepository, 0, len(scenarios))
	for _, item := range scenarios {
		status := item.attachment
		if status == "" {
			status = "attached"
		}
		entry := configurationRepository{Status: status}
		entry.Repository.Name = item.name
		entry.Repository.FullName = testOrg + "/" + item.name
		attachments = append(attachments, entry)
	}
	client.set(fmt.Sprintf("orgs/%s/code-security/configurations/1/repositories?", testOrg), attachments)

	properties := make([]propertyValues, 0, len(scenarios))
	for _, item := range scenarios {
		properties = append(properties, propertyValues{
			RepositoryName: item.name,
			Properties: []struct {
				PropertyName string `json:"property_name"`
				Value        any    `json:"value"`
			}{{PropertyName: "application", Value: "app-" + item.name}},
		})
	}
	client.set(fmt.Sprintf("orgs/%s/properties/values?", testOrg), properties)

	// Repository level endpoints.
	for _, item := range scenarios {
		base := fmt.Sprintf("repos/%s/%s/", testOrg, item.name)
		if item.defaultSetup != nil {
			client.set(base+"code-scanning/default-setup", item.defaultSetup)
		}
		if item.workflows != nil {
			client.set(base+"actions/workflows", item.workflows)
		}
		for suffix, value := range item.runs {
			client.set(base+"actions/workflows/99/runs?"+suffix, value)
		}
		if item.jobs != nil {
			client.set(base+"actions/runs/", item.jobs)
		}
		if item.databases != nil {
			client.set(base+"code-scanning/codeql/databases", item.databases)
		}
	}

	return client
}

func codeqlWorkflows() workflowList {
	return workflowList{
		TotalCount: 1,
		Workflows: []struct {
			ID    int64  `json:"id"`
			Name  string `json:"name"`
			Path  string `json:"path"`
			State string `json:"state"`
		}{{ID: 99, Name: "CodeQL", Path: codeqlWorkflowPath, State: "active"}},
	}
}

func runList(conclusion string, age time.Duration) workflowRunList {
	return runListFor(codeqlWorkflowPath, conclusion, age)
}

// advancedWorkflows builds a workflow list for a repository-controlled CodeQL
// workflow, which has no fixed path.
func advancedWorkflows(path string) workflowList {
	return workflowList{
		TotalCount: 1,
		Workflows: []struct {
			ID    int64  `json:"id"`
			Name  string `json:"name"`
			Path  string `json:"path"`
			State string `json:"state"`
		}{{ID: 99, Name: "CodeQL Advanced", Path: path, State: "active"}},
	}
}

func runListFor(path, conclusion string, age time.Duration) workflowRunList {
	moment := time.Now().Add(-age)
	return workflowRunList{
		TotalCount: 1,
		WorkflowRun: []workflowRun{{
			ID:           1234,
			Path:         path,
			Status:       "completed",
			Conclusion:   conclusion,
			Event:        "dynamic",
			HeadBranch:   "main",
			RunStartedAt: &moment,
			UpdatedAt:    &moment,
			HTMLURL:      "https://github.com/run/1234",
			RunAttempt:   1,
		}},
	}
}

func jobsFor(results map[string]string) jobList {
	list := jobList{}
	for language, conclusion := range results {
		list.Jobs = append(list.Jobs, job{
			ID:         1,
			Name:       fmt.Sprintf("Analyze (%s)", language),
			Status:     "completed",
			Conclusion: conclusion,
			HTMLURL:    "https://github.com/job/" + language,
		})
	}
	list.TotalCount = len(list.Jobs)
	return list
}

func databasesFor(languages []string, age time.Duration) []codeqlDatabase {
	moment := time.Now().Add(-age)
	databases := make([]codeqlDatabase, 0, len(languages))
	for _, language := range languages {
		databases = append(databases, codeqlDatabase{
			ID: 1, Name: language + "-database", Language: language,
			CreatedAt: &moment, UpdatedAt: &moment,
		})
	}
	return databases
}

func collect(t *testing.T, client Client, options Options) *model.Report {
	t.Helper()
	if options.Organizations == nil {
		options.Organizations = []string{testOrg}
	}
	if options.StaleAfter == 0 {
		options.StaleAfter = 8 * 24 * time.Hour
	}
	options.Concurrency = 1

	report, err := New(client, options).Collect(context.Background(), "test")
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	return report
}

func findRepo(t *testing.T, report *model.Report, name string) model.Repo {
	t.Helper()
	for _, repo := range report.Repositories {
		if repo.Name == name {
			return repo
		}
	}
	t.Fatalf("repository %q not found in report", name)
	return model.Repo{}
}

func TestHealthyRepositoryIsReportedHealthy(t *testing.T) {
	client := buildClient(t, scenario{
		name:      "healthy",
		languages: []string{"Go", "Dockerfile"},
		defaultSetup: defaultSetup{
			State: "configured", Languages: []string{"go", "actions"},
			QuerySuite: "default", Schedule: "weekly",
		},
		workflows: codeqlWorkflows(),
		runs: map[string]any{
			"": runList("success", 2*24*time.Hour),
		},
		jobs:      jobsFor(map[string]string{"go": "success", "actions": "success"}),
		databases: databasesFor([]string{"go", "actions"}, 2*24*time.Hour),
	})

	repo := findRepo(t, collect(t, client, Options{}), "healthy")

	if repo.Status.Overall != model.SeverityHealthy {
		t.Fatalf("overall = %q, want healthy (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
	if repo.Status.Coverage != model.CoverageComplete {
		t.Errorf("coverage = %q, want complete", repo.Status.Coverage)
	}
	if repo.Status.Freshness != model.FreshCurrent {
		t.Errorf("freshness = %q, want current", repo.Status.Freshness)
	}
	if len(repo.SucceededLanguages) != 2 {
		t.Errorf("succeeded languages = %v, want go and actions", repo.SucceededLanguages)
	}
	if repo.LastSuccessfulScan == nil {
		t.Error("a healthy repository must record when it last scanned successfully")
	}
}

// This is the failure mode customers report most often: the workflow is green,
// so every coverage view shows the repository as protected, while one language
// silently produced nothing.
func TestGreenRunWithUnanalyzedLanguageIsDegraded(t *testing.T) {
	client := buildClient(t, scenario{
		name:      "partial",
		languages: []string{"Java", "Python"},
		defaultSetup: defaultSetup{
			State: "configured", Languages: []string{"java-kotlin", "python"},
		},
		workflows: codeqlWorkflows(),
		runs: map[string]any{
			"": runList("success", 1*24*time.Hour),
		},
		jobs:      jobsFor(map[string]string{"java-kotlin": "success", "python": "failure"}),
		databases: databasesFor([]string{"java"}, 1*24*time.Hour),
	})

	repo := findRepo(t, collect(t, client, Options{}), "partial")

	if repo.Status.Execution != model.ExecSuccess {
		t.Fatalf("execution = %q, want success; the run itself passed", repo.Status.Execution)
	}
	if repo.Status.Overall != model.SeverityDegraded {
		t.Fatalf("overall = %q, want degraded (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
	if repo.Status.Coverage != model.CoveragePartial {
		t.Errorf("coverage = %q, want partial", repo.Status.Coverage)
	}
	if len(repo.FailedLanguages) != 1 || repo.FailedLanguages[0] != model.LangPython {
		t.Errorf("failed languages = %v, want [python]", repo.FailedLanguages)
	}

	var found bool
	for _, diagnostic := range repo.Diagnostics {
		if diagnostic.Code == "language-not-analyzed" && diagnostic.Language == model.LangPython {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a language-not-analyzed diagnostic, got %+v", repo.Diagnostics)
	}
}

func TestDetectedLanguageNotConfiguredIsReportedAsGap(t *testing.T) {
	client := buildClient(t, scenario{
		name:      "drift",
		languages: []string{"Go", "Python"},
		defaultSetup: defaultSetup{
			State: "configured", Languages: []string{"go"},
		},
		workflows: codeqlWorkflows(),
		runs: map[string]any{
			"": runList("success", 1*24*time.Hour),
		},
		jobs:      jobsFor(map[string]string{"go": "success"}),
		databases: databasesFor([]string{"go"}, 1*24*time.Hour),
	})

	repo := findRepo(t, collect(t, client, Options{}), "drift")

	if repo.Status.Coverage != model.CoverageGap {
		t.Fatalf("coverage = %q, want gap", repo.Status.Coverage)
	}
	if repo.Status.Overall != model.SeverityDegraded {
		t.Fatalf("overall = %q, want degraded", repo.Status.Overall)
	}
	if len(repo.MissingLanguages) != 1 || repo.MissingLanguages[0] != model.LangPython {
		t.Errorf("missing languages = %v, want [python]", repo.MissingLanguages)
	}
}

// Actions is not reported by source language detection, so it must never be
// counted as an unconfigured coverage gap.
func TestActionsIsNeverReportedAsAMissingLanguage(t *testing.T) {
	client := buildClient(t, scenario{
		name:      "actions-only",
		languages: []string{"Go"},
		defaultSetup: defaultSetup{
			State: "configured", Languages: []string{"go", "actions"},
		},
		workflows: codeqlWorkflows(),
		runs: map[string]any{
			"": runList("success", time.Hour),
		},
		jobs:      jobsFor(map[string]string{"go": "success", "actions": "success"}),
		databases: databasesFor([]string{"go", "actions"}, time.Hour),
	})

	repo := findRepo(t, collect(t, client, Options{}), "actions-only")
	for _, language := range repo.MissingLanguages {
		if language == model.LangActions {
			t.Fatal("actions must not be reported as a missing language")
		}
	}
	if repo.Status.Overall != model.SeverityHealthy {
		t.Fatalf("overall = %q, want healthy (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
}

func TestConfiguredRepositoryWithNoWorkflowIsStalled(t *testing.T) {
	client := buildClient(t, scenario{
		name:      "never-provisioned",
		languages: []string{"Go"},
		defaultSetup: defaultSetup{
			State: "configured", Languages: []string{"go"},
		},
		workflows: workflowList{TotalCount: 0},
	})

	repo := findRepo(t, collect(t, client, Options{}), "never-provisioned")

	if repo.Status.Overall != model.SeverityStalled {
		t.Fatalf("overall = %q, want stalled (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
	if repo.Status.Execution != model.ExecNoWorkflow {
		t.Errorf("execution = %q, want no-workflow", repo.Status.Execution)
	}
	if repo.Status.Freshness != model.FreshNever {
		t.Errorf("freshness = %q, want never-scanned", repo.Status.Freshness)
	}
}

// An empty repository keeps default setup "configured" forever. Reporting
// those as stalled would bury genuine failures in noise.
func TestEmptyRepositoryIsNotApplicable(t *testing.T) {
	client := buildClient(t, scenario{
		name:         "empty",
		languages:    nil,
		defaultSetup: defaultSetup{State: "configured"},
		workflows:    workflowList{TotalCount: 0},
	})

	repo := findRepo(t, collect(t, client, Options{}), "empty")
	if repo.Status.Overall != model.SeverityNotApplicable {
		t.Fatalf("overall = %q, want not-applicable (reasons: %v)", repo.Status.Overall, repo.Status.Reasons)
	}
}

func TestStaleRepositoryIsReportedAgainstTheThreshold(t *testing.T) {
	client := buildClient(t, scenario{
		name:      "stale",
		languages: []string{"Go"},
		defaultSetup: defaultSetup{
			State: "configured", Languages: []string{"go"}, Schedule: "weekly",
		},
		workflows: codeqlWorkflows(),
		runs: map[string]any{
			"": runList("success", 30*24*time.Hour),
		},
		jobs:      jobsFor(map[string]string{"go": "success"}),
		databases: databasesFor([]string{"go"}, 30*24*time.Hour),
	})

	report := collect(t, client, Options{StaleAfter: 8 * 24 * time.Hour})
	repo := findRepo(t, report, "stale")

	if repo.Status.Overall != model.SeverityStale {
		t.Fatalf("overall = %q, want stale", repo.Status.Overall)
	}
	if repo.StaleDays == nil || *repo.StaleDays < 29 {
		t.Errorf("stale days = %v, want about 30", repo.StaleDays)
	}

	// The same repository is healthy under a longer threshold, proving the
	// threshold rather than a hard-coded window drives the classification.
	relaxed := collect(t, client, Options{StaleAfter: 90 * 24 * time.Hour})
	if got := findRepo(t, relaxed, "stale"); got.Status.Overall != model.SeverityHealthy {
		t.Errorf("with a 90d threshold overall = %q, want healthy", got.Status.Overall)
	}
}

func TestFailedRunIsReportedFailing(t *testing.T) {
	client := buildClient(t, scenario{
		name:      "failing",
		languages: []string{"Java"},
		defaultSetup: defaultSetup{
			State: "configured", Languages: []string{"java-kotlin"},
		},
		workflows: codeqlWorkflows(),
		runs: map[string]any{
			"": runList("failure", time.Hour),
		},
		jobs: jobsFor(map[string]string{"java-kotlin": "failure"}),
	})

	repo := findRepo(t, collect(t, client, Options{}), "failing")
	if repo.Status.Overall != model.SeverityFailing {
		t.Fatalf("overall = %q, want failing", repo.Status.Overall)
	}
	if repo.Execution.LatestCompletedRun == nil || repo.Execution.LatestCompletedRun.URL == "" {
		t.Error("a failing repository must link to the run as evidence")
	}
}

func TestUnlicensedRepositoryIsUnavailableNotHealthy(t *testing.T) {
	client := buildClient(t, scenario{
		name:      "no-license",
		languages: []string{"Go"},
	})

	repo := findRepo(t, collect(t, client, Options{}), "no-license")
	if repo.Status.Overall != model.SeverityUnavailable {
		t.Fatalf("overall = %q, want unavailable", repo.Status.Overall)
	}
	if repo.Status.Configuration != model.ConfigUnavailable {
		t.Errorf("configuration = %q, want unavailable", repo.Status.Configuration)
	}
}

func TestFailedConfigurationAttachmentIsSurfaced(t *testing.T) {
	client := buildClient(t, scenario{
		name:         "attach-failed",
		languages:    []string{"Go"},
		attachment:   "failed",
		defaultSetup: defaultSetup{State: "not-configured"},
	})

	repo := findRepo(t, collect(t, client, Options{}), "attach-failed")
	if repo.Status.Overall != model.SeverityStalled {
		t.Fatalf("overall = %q, want stalled", repo.Status.Overall)
	}
	if repo.Configuration.AttachmentStatus != "failed" {
		t.Errorf("attachment status = %q, want failed", repo.Configuration.AttachmentStatus)
	}
	var found bool
	for _, diagnostic := range repo.Diagnostics {
		if diagnostic.Code == "configuration-attach-failed" {
			found = true
		}
	}
	if !found {
		t.Error("a failed attachment must produce a diagnostic")
	}
}

func TestCustomPropertiesAreCollectedAndGrouped(t *testing.T) {
	client := buildClient(t,
		scenario{
			name: "one", languages: []string{"Go"},
			defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
			workflows:    codeqlWorkflows(),
			runs:         map[string]any{"": runList("success", time.Hour)},
			jobs:         jobsFor(map[string]string{"go": "success"}),
			databases:    databasesFor([]string{"go"}, time.Hour),
		},
		scenario{
			name: "two", languages: []string{"Go"},
			defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
			workflows:    workflowList{TotalCount: 0},
		},
	)

	report := collect(t, client, Options{GroupByProperty: "application"})

	repo := findRepo(t, report, "one")
	if repo.Properties["application"] != "app-one" {
		t.Errorf("application property = %q, want app-one", repo.Properties["application"])
	}
	if len(report.Summary.Groups) != 2 {
		t.Fatalf("got %d groups, want 2", len(report.Summary.Groups))
	}
	// Groups needing attention must sort first so triage starts at the top.
	if report.Summary.Groups[0].NeedsAttention == 0 {
		t.Errorf("groups must be ordered with problems first, got %+v", report.Summary.Groups)
	}
}

func TestRepositoryFiltersAvoidUnnecessaryRequests(t *testing.T) {
	client := buildClient(t,
		scenario{name: "keep-me", languages: []string{"Go"},
			defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
			workflows:    codeqlWorkflows(),
			runs:         map[string]any{"": runList("success", time.Hour)},
			jobs:         jobsFor(map[string]string{"go": "success"}),
			databases:    databasesFor([]string{"go"}, time.Hour)},
		scenario{name: "skip-me", languages: []string{"Go"},
			defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
			workflows:    codeqlWorkflows()},
	)

	report := collect(t, client, Options{ExcludeFilter: []string{"skip-*"}})

	if len(report.Repositories) != 1 || report.Repositories[0].Name != "keep-me" {
		t.Fatalf("expected only keep-me, got %d repositories", len(report.Repositories))
	}
	for _, request := range client.requests {
		if strings.Contains(request, "skip-me") {
			t.Fatalf("excluded repositories must not be queried, saw %q", request)
		}
	}
}

func TestSummaryCountsAndSortingReflectUrgency(t *testing.T) {
	client := buildClient(t,
		scenario{name: "aaa-healthy", languages: []string{"Go"},
			defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
			workflows:    codeqlWorkflows(),
			runs:         map[string]any{"": runList("success", time.Hour)},
			jobs:         jobsFor(map[string]string{"go": "success"}),
			databases:    databasesFor([]string{"go"}, time.Hour)},
		scenario{name: "zzz-failing", languages: []string{"Go"},
			defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
			workflows:    codeqlWorkflows(),
			runs:         map[string]any{"": runList("failure", time.Hour)},
			jobs:         jobsFor(map[string]string{"go": "failure"})},
	)

	report := collect(t, client, Options{})

	if report.Repositories[0].Name != "zzz-failing" {
		t.Errorf("most urgent repository must sort first, got %q", report.Repositories[0].Name)
	}
	if report.Summary.NeedsAttention != 1 {
		t.Errorf("needs attention = %d, want 1", report.Summary.NeedsAttention)
	}
	if report.Summary.BySeverity[string(model.SeverityFailing)] != 1 {
		t.Errorf("failing count = %d, want 1", report.Summary.BySeverity[string(model.SeverityFailing)])
	}
	if report.SchemaVersion != model.SchemaVersion {
		t.Errorf("schema version = %q, want %q", report.SchemaVersion, model.SchemaVersion)
	}
}

func TestLanguageFromJobName(t *testing.T) {
	cases := map[string]model.Language{
		"Analyze (java-kotlin)":           model.LangJavaKotlin,
		"Analyze (javascript-typescript)": model.LangJavaScriptTypeScript,
		"Analyze (go, ubuntu-latest)":     model.LangGo,
		"Analyze (python) / build":        model.LangPython,
		"CodeQL Analysis (csharp)":        model.LangCSharp,
	}
	for name, want := range cases {
		got, ok := languageFromJobName(name)
		if !ok || got != want {
			t.Errorf("languageFromJobName(%q) = %q, %v; want %q", name, got, ok, want)
		}
	}

	for _, name := range []string{"Set up job", "Analyze", "Build (ubuntu-latest)"} {
		if language, ok := languageFromJobName(name); ok {
			t.Errorf("languageFromJobName(%q) unexpectedly matched %q", name, language)
		}
	}
}

func TestFormatPropertyValue(t *testing.T) {
	cases := []struct {
		input any
		want  string
	}{
		{nil, ""},
		{"payments", "payments"},
		{true, "true"},
		{false, "false"},
		{[]any{"a", "b"}, "a, b"},
	}
	for _, test := range cases {
		if got := formatPropertyValue(test.input); got != test.want {
			t.Errorf("formatPropertyValue(%v) = %q, want %q", test.input, got, test.want)
		}
	}
}

func TestMatchesAnySupportsGlobs(t *testing.T) {
	if !matchesAny("team-payments", []string{"team-*"}) {
		t.Error("prefix glob should match")
	}
	if !matchesAny("payments-api", []string{"*-api"}) {
		t.Error("suffix glob should match")
	}
	if matchesAny("payments-api", []string{"team-*"}) {
		t.Error("non-matching glob must not match")
	}
	if !matchesAny("exact", []string{"EXACT"}) {
		t.Error("matching should be case-insensitive")
	}
}
