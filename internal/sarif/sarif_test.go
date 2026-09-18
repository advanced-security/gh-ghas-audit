package sarif

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/ghapi"
	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
)

// javaSARIF reproduces the shape of a real code-scanning-analyses SARIF
// response for a standard CodeQL java-kotlin analysis: one run, a query pack
// extension carrying rule IDs, artifacts, and a mix of result levels.
const javaSARIF = `{
  "runs": [
    {
      "tool": {
        "driver": {"name": "CodeQL", "semanticVersion": "2.20.3"},
        "extensions": [
          {
            "name": "codeql/java-queries",
            "version": "1.2.3",
            "rules": [{"id": "java/unused-import"}, {"id": "java/sql-injection"}]
          }
        ]
      },
      "artifacts": [{}, {}, {}],
      "results": [
        {"ruleId": "java/sql-injection", "level": "error"},
        {"ruleId": "java/unused-import", "level": "warning"},
        {"ruleId": "java/unused-import", "level": "warning"}
      ]
    }
  ]
}`

func TestParseExtractsQueryPacksRulesAndResults(t *testing.T) {
	result, err := Parse([]byte(javaSARIF))
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	if result.Language != model.LangJavaKotlin {
		t.Errorf("Language = %q, want %q", result.Language, model.LangJavaKotlin)
	}
	if result.CodeQLVersion != "2.20.3" {
		t.Errorf("CodeQLVersion = %q, want 2.20.3", result.CodeQLVersion)
	}
	if len(result.QueryPacks) != 1 || result.QueryPacks[0] != "codeql/java-queries@1.2.3" {
		t.Errorf("QueryPacks = %v, want [codeql/java-queries@1.2.3]", result.QueryPacks)
	}
	if result.RuleCount != 2 {
		t.Errorf("RuleCount = %d, want 2", result.RuleCount)
	}
	if result.ArtifactCount != 3 {
		t.Errorf("ArtifactCount = %d, want 3", result.ArtifactCount)
	}
	if result.ResultsByLevel["error"] != 1 || result.ResultsByLevel["warning"] != 2 {
		t.Errorf("ResultsByLevel = %v, want error:1 warning:2", result.ResultsByLevel)
	}
}

// A custom or API-based upload can name its category anything, so the
// category-vs-SARIF mismatch check depends on this fallback: when a SARIF
// document carries no query pack extension (only driver rules), the language
// must still be inferred from the rule ID's own prefix.
func TestParseInfersLanguageFromRuleIDWhenPacksAreAbsent(t *testing.T) {
	const doc = `{
		"runs": [{
			"tool": {"driver": {"name": "CodeQL", "rules": [{"id": "cs/sql-injection"}]}},
			"results": [{"ruleId": "cs/sql-injection", "level": "error"}]
		}]
	}`
	result, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	if result.Language != model.LangCSharp {
		t.Errorf("Language = %q, want %q", result.Language, model.LangCSharp)
	}
	if len(result.QueryPacks) != 0 {
		t.Errorf("QueryPacks = %v, want none without an extension", result.QueryPacks)
	}
}

// A minimal, hand-built SARIF document can carry results without ever
// declaring them under tool.driver.rules or an extension; the rule-ID
// fallback must still inspect results[].ruleId, without counting those rule
// IDs into RuleCount, which only reflects declared rules.
func TestParseInfersLanguageFromResultRuleIDWhenRulesAreUndeclared(t *testing.T) {
	const doc = `{
		"runs": [{
			"tool": {"driver": {"name": "CodeQL"}},
			"results": [{"ruleId": "cs/sql-injection", "level": "error"}]
		}]
	}`
	result, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	if result.Language != model.LangCSharp {
		t.Errorf("Language = %q, want %q", result.Language, model.LangCSharp)
	}
	if result.RuleCount != 0 {
		t.Errorf("RuleCount = %d, want 0 (results are not declared rules)", result.RuleCount)
	}
}

// A custom or org-specific query pack keeps the language prefix but appends
// its own suffix, e.g. "octo-org/csharp-extra-queries", which does not match
// any packPrefixLanguages key exactly; the prefix must still resolve.
func TestParseInfersLanguageFromCustomQueryPackSuffix(t *testing.T) {
	const doc = `{
		"runs": [{
			"tool": {
				"driver": {"name": "CodeQL"},
				"extensions": [{"name": "octo-org/csharp-extra-queries", "rules": [{"id": "cs/sql-injection"}]}]
			},
			"results": [{"ruleId": "cs/sql-injection", "level": "error"}]
		}]
	}`
	result, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	if result.Language != model.LangCSharp {
		t.Errorf("Language = %q, want %q", result.Language, model.LangCSharp)
	}
}

// A clean analysis with zero findings is a legitimate, common outcome and
// must be distinguishable from a SARIF document that could not be parsed.
func TestParseHandlesZeroResults(t *testing.T) {
	const doc = `{
		"runs": [{
			"tool": {"driver": {"name": "CodeQL", "semanticVersion": "2.20.3"}},
			"results": []
		}]
	}`
	result, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	if len(result.ResultsByLevel) != 0 {
		t.Errorf("ResultsByLevel = %v, want empty for zero results", result.ResultsByLevel)
	}
	if result.RuleCount != 0 {
		t.Errorf("RuleCount = %d, want 0", result.RuleCount)
	}
}

// A minimal or hand-built SARIF document (no runs at all) must be parsed
// without error rather than treated as a decode failure.
func TestParseHandlesMinimalSARIF(t *testing.T) {
	result, err := Parse([]byte(`{"runs": []}`))
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	if result.Language != "" || result.RuleCount != 0 || len(result.QueryPacks) != 0 {
		t.Errorf("expected a bare empty result, got %+v", result)
	}
}

func TestParseRejectsInvalidJSON(t *testing.T) {
	if _, err := Parse([]byte("not json")); err == nil {
		t.Fatal("invalid SARIF must be reported rather than silently ignored")
	}
}

// A result with no explicit "level" defaults to "warning", matching CodeQL's
// own default severity, not SARIF's schema default.
func TestParseDefaultsMissingLevelToWarning(t *testing.T) {
	const doc = `{
		"runs": [{
			"tool": {"driver": {"name": "CodeQL"}},
			"results": [{"ruleId": "java/unused-import"}]
		}]
	}`
	result, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	if result.ResultsByLevel["warning"] != 1 {
		t.Errorf("ResultsByLevel = %v, want warning:1", result.ResultsByLevel)
	}
}

// fakeClient stands in for ghapi.Client, letting Fetcher tests exercise
// budget and error handling without any network access.
type fakeClient struct {
	body  []byte
	err   error
	calls atomic.Int64
}

func (c *fakeClient) Host() string { return "github.com" }

func (c *fakeClient) GetSARIFLimited(_ context.Context, _ string, limit int64) ([]byte, error) {
	c.calls.Add(1)
	if c.err != nil {
		return nil, c.err
	}
	if int64(len(c.body)) > limit {
		return nil, ghapi.ErrResponseTooLarge
	}
	return c.body, nil
}

func TestNewFetcherAppliesDefaults(t *testing.T) {
	fetcher := NewFetcher(nil, Limits{})
	if fetcher.limits.MaxRepositories != defaultMaxRepositories || fetcher.limits.MaxBytes != defaultMaxBytes {
		t.Fatalf("zero limits must fall back to defaults, got %+v", fetcher.limits)
	}
}

func TestInspectReservesOncePerRepositoryAcrossLanguages(t *testing.T) {
	client := &fakeClient{body: []byte(javaSARIF)}
	fetcher := NewFetcher(client, Limits{MaxRepositories: 1, MaxBytes: 1 << 20})

	analyses := []Analysis{
		{Language: model.LangJavaKotlin, AnalysisID: 1},
		{Language: model.LangPython, AnalysisID: 2},
		{Language: model.LangGo, AnalysisID: 3},
	}
	results, err := fetcher.Inspect(context.Background(), "org", "repo", analyses)
	if err != nil {
		t.Fatalf("Inspect returned an error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want one per language", len(results))
	}
	if fetcher.inspected.Load() != 1 {
		t.Fatalf("a polyglot repository consumed %d repository slots, want 1", fetcher.inspected.Load())
	}
	if got, want := client.calls.Load(), int64(3); got != want {
		t.Fatalf("expected one download per language, got %d calls", got)
	}
	if got, want := fetcher.BytesDownloaded(), int64(3*len(javaSARIF)); got != want {
		t.Fatalf("BytesDownloaded = %d, want %d (charged once per language against the shared budget)", got, want)
	}
}

// When the shared budget runs out partway through a polyglot repository,
// whatever succeeded first must still be returned rather than discarded.
func TestInspectReturnsPartialResultsOnBudgetExhaustion(t *testing.T) {
	client := &fakeClient{body: []byte(javaSARIF)}
	fetcher := NewFetcher(client, Limits{MaxRepositories: 1, MaxBytes: int64(len(javaSARIF))})

	analyses := []Analysis{
		{Language: model.LangJavaKotlin, AnalysisID: 1},
		{Language: model.LangPython, AnalysisID: 2},
	}
	results, err := fetcher.Inspect(context.Background(), "org", "repo", analyses)
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("expected ErrBudgetExhausted, got %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d partial results, want 1 kept from before the budget ran out", len(results))
	}
	if _, ok := results[model.LangJavaKotlin]; !ok {
		t.Fatalf("expected the first language's result to survive, got %v", results)
	}
}

func TestInspectStopsWhenSARIFExceedsRemainingBudget(t *testing.T) {
	client := &fakeClient{body: []byte(javaSARIF)}
	fetcher := NewFetcher(client, Limits{MaxRepositories: 1, MaxBytes: 1})

	_, err := fetcher.Inspect(context.Background(), "org", "repo", []Analysis{{AnalysisID: 1}})
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("an oversized SARIF response must be reported as budget exhaustion, got %v", err)
	}
}

func TestInspectReportsUnavailableSARIF(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden} {
		apiErr := &ghapi.StatusError{StatusCode: status, Message: "SARIF unavailable"}
		fetcher := NewFetcher(&fakeClient{err: apiErr}, Limits{})
		_, err := fetcher.Inspect(context.Background(), "org", "repo", []Analysis{{AnalysisID: 1}})
		if !errors.Is(err, apiErr) {
			t.Fatalf("status %d must propagate its error, got %v", status, err)
		}
	}
}

func TestInspectHonorsRepositoryBudget(t *testing.T) {
	client := &fakeClient{body: []byte(javaSARIF)}
	fetcher := NewFetcher(client, Limits{MaxRepositories: 1, MaxBytes: 1 << 20})

	if _, err := fetcher.Inspect(context.Background(), "org", "one", []Analysis{{AnalysisID: 1}}); err != nil {
		t.Fatalf("first repository should have budget: %v", err)
	}
	_, err := fetcher.Inspect(context.Background(), "org", "two", []Analysis{{AnalysisID: 2}})
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("a second repository beyond the cap must be reported as budget exhaustion, got %v", err)
	}
}

func TestInspectIgnoresEmptyAnalysisList(t *testing.T) {
	fetcher := NewFetcher(&fakeClient{}, Limits{})
	results, err := fetcher.Inspect(context.Background(), "org", "repo", nil)
	if err != nil || results != nil {
		t.Fatalf("an empty analysis list must be a no-op, got %v, %v", results, err)
	}
	if fetcher.inspected.Load() != 0 {
		t.Fatal("a repository with nothing to fetch must not consume a repository slot")
	}
}

func TestCancelledInspectionDoesNotDownload(t *testing.T) {
	client := &fakeClient{body: []byte(javaSARIF)}
	fetcher := NewFetcher(client, Limits{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fetcher.Inspect(ctx, "org", "repo", []Analysis{{AnalysisID: 1}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if client.calls.Load() != 0 {
		t.Fatal("cancelled inspection downloaded SARIF")
	}
}

func TestBudgetMessagesDistinguishRepositoriesFromBytes(t *testing.T) {
	repoFetcher := NewFetcher(nil, Limits{MaxRepositories: 1, MaxBytes: 1 << 20})
	repoFetcher.inspected.Add(1)
	if exhausted, message := repoFetcher.Budget(); !exhausted || message == "" {
		t.Fatal("a spent repository budget must be reported as exhausted, with an explanation")
	}

	byteFetcher := NewFetcher(nil, Limits{MaxRepositories: 10, MaxBytes: 1024})
	byteFetcher.bytesRead.Store(1024)
	if exhausted, message := byteFetcher.Budget(); !exhausted || message == "" {
		t.Fatal("a spent byte budget must be reported as exhausted, with an explanation")
	}
}
