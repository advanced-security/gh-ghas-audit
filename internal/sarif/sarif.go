// Package sarif implements the opt-in download and structural parsing of a
// code scanning analysis's SARIF representation, used at --scan-depth
// diagnostics unless disabled with --no-sarif.
//
// The analyses list and default setup APIs answer "which category/language
// was this analysis uploaded under", but that category is a caller-supplied
// string: a custom workflow or an API-based upload can name it anything.
// SARIF's query pack names and rule IDs are a tamper-resistant, independent
// signal of what CodeQL actually scanned, which this package extracts to
// cross-check the category-derived language.
//
// Only structural fields are read: query pack names/versions, rule IDs,
// result severities and artifact counts. Result messages, locations and
// source snippets are deliberately never parsed or retained, because SARIF
// for a private repository can carry source excerpts that the rest of this
// tool's evidence never touches.
//
// This package only ever requests the SARIF representation documented at
// GET /repos/{owner}/{repo}/code-scanning/analyses/{analysis_id}. It does not
// read the much larger raw SARIF a CodeQL CLI run uploads as a workflow
// artifact, which can carry extraction diagnostics and line-of-code metrics
// this representation strips.
package sarif

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/ghapi"
	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
)

// Defaults chosen to keep an opt-in SARIF pass bounded even when a user points
// it at a large estate. They are only applied to a zero-value Limits; the CLI
// translates an explicit "0" flag value to true-unlimited before it ever
// reaches NewFetcher, so these defaults exist for library callers and tests
// that construct Limits{} without every field set.
const (
	defaultMaxRepositories = 200
	defaultMaxBytes        = 1 << 30 // 1 GiB of SARIF per run
)

// ErrBudgetExhausted distinguishes an uninspected analysis from one that
// genuinely produced no SARIF.
var ErrBudgetExhausted = errors.New("SARIF download budget exhausted")

// Limits bounds the work a SARIF pass may perform.
type Limits struct {
	// MaxRepositories caps how many repositories have SARIF downloaded.
	MaxRepositories int
	// MaxBytes caps the total SARIF bytes downloaded across every repository
	// and language in the run.
	MaxBytes int64
}

// Analysis identifies one language's analysis to fetch SARIF for.
type Analysis struct {
	Language   model.Language
	AnalysisID int64
}

// Result is the structural evidence extracted from one analysis's SARIF.
type Result struct {
	// Language is inferred from the SARIF query pack names or rule ID
	// prefixes, independent of the category the analysis was uploaded under.
	Language model.Language
	// CodeQLVersion is the tool driver's version, preferring semanticVersion.
	CodeQLVersion string
	// QueryPacks lists each query pack as "name@version", sorted for stable
	// output.
	QueryPacks []string
	// RuleCount is the number of distinct rule IDs across the tool driver and
	// its extensions.
	RuleCount int
	// ResultsByLevel counts results by SARIF level (error, warning, note).
	ResultsByLevel map[string]int
	// ArtifactCount is the number of source artifacts SARIF recorded.
	ArtifactCount int
}

type sarifClient interface {
	GetSARIFLimited(ctx context.Context, path string, limit int64) ([]byte, error)
	Host() string
}

// Fetcher downloads and parses SARIF within configured limits.
//
// Reservation happens once per repository, mirroring internal/diagnostics:
// every language analysis for that repository is then fetched against the
// same shared byte budget, so a polyglot repository is not double-charged
// against the repository cap for needing several SARIF downloads.
type Fetcher struct {
	client       sarifClient
	limits       Limits
	downloadSlot chan struct{}

	inspected atomic.Int64
	bytesRead atomic.Int64
}

// NewFetcher creates a Fetcher with sane defaults applied to zero values.
func NewFetcher(client sarifClient, limits Limits) *Fetcher {
	if limits.MaxRepositories <= 0 {
		limits.MaxRepositories = defaultMaxRepositories
	}
	if limits.MaxBytes <= 0 {
		limits.MaxBytes = defaultMaxBytes
	}
	return &Fetcher{client: client, limits: limits, downloadSlot: make(chan struct{}, 1)}
}

// BytesDownloaded reports the total SARIF bytes downloaded so far, for
// end-of-run reporting.
func (f *Fetcher) BytesDownloaded() int64 { return f.bytesRead.Load() }

// Budget reports whether the fetcher has exhausted its limits, and a message
// explaining which limit was reached. It combines both limits and is meant
// for callers deciding whether to start work on a new repository.
func (f *Fetcher) Budget() (bool, string) {
	if f.inspected.Load() >= int64(f.limits.MaxRepositories) {
		return true, fmt.Sprintf(
			"SARIF collection stopped after %d repositories; raise --deep-diagnostics-max-repos to inspect more",
			f.limits.MaxRepositories)
	}
	return f.bytesExhausted()
}

// bytesExhausted reports only the byte budget, independent of the repository
// count. fetchOne must use this rather than Budget: a repository's slot is
// reserved once for however many per-language analyses it has, so checking
// the repository cap again for its second and later languages would treat an
// already-reserved repository as if it were a new, unreserved one, wrongly
// stopping every language after the first once the cap is reached.
func (f *Fetcher) bytesExhausted() (bool, string) {
	if f.bytesRead.Load() >= f.limits.MaxBytes {
		return true, fmt.Sprintf(
			"SARIF collection stopped after downloading %d MiB; raise --deep-diagnostics-max-sarif-mb to inspect more",
			f.limits.MaxBytes>>20)
	}
	return false, ""
}

// reserveRepository atomically claims one repository slot, returning false
// when the limit is already taken. See internal/diagnostics.Fetcher.reserve
// for why this must be a CAS loop rather than a check followed by an
// increment.
func (f *Fetcher) reserveRepository() bool {
	for {
		current := f.inspected.Load()
		if current >= int64(f.limits.MaxRepositories) {
			return false
		}
		if f.inspected.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

// remainingBytes returns how much of the byte budget is still unspent.
func (f *Fetcher) remainingBytes() int64 {
	remaining := f.limits.MaxBytes - f.bytesRead.Load()
	if remaining < 0 {
		return 0
	}
	return remaining
}

// Inspect downloads SARIF for each of a repository's current per-language
// analyses and returns structural findings, keyed by language.
//
// A returned error means SARIF collection for this repository was not fully
// completed (for example the shared budget ran out partway through). Results
// already collected for other languages are still returned alongside it, so
// a partial download is not discarded.
func (f *Fetcher) Inspect(ctx context.Context, org, repo string, analyses []Analysis) (map[model.Language]*Result, error) {
	if len(analyses) == 0 {
		return nil, nil
	}
	if exhausted, message := f.Budget(); exhausted {
		return nil, fmt.Errorf("%w: %s", ErrBudgetExhausted, message)
	}
	if !f.reserveRepository() {
		return nil, fmt.Errorf("%w: maximum of %d repositories inspected",
			ErrBudgetExhausted, f.limits.MaxRepositories)
	}

	results := make(map[model.Language]*Result, len(analyses))
	var firstErr error
	for _, analysis := range analyses {
		result, err := f.fetchOne(ctx, org, repo, analysis.AnalysisID)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", analysis.Language, err)
			}
			if errors.Is(err, ErrBudgetExhausted) || ctx.Err() != nil {
				// The budget or the run is spent; further languages would
				// only repeat the same failure.
				break
			}
			continue
		}
		results[analysis.Language] = result
	}
	return results, firstErr
}

// fetchOne downloads and parses the SARIF for a single analysis ID.
func (f *Fetcher) fetchOne(ctx context.Context, org, repo string, analysisID int64) (*Result, error) {
	// Response sizes are unknown until downloaded. Serialize downloads so
	// concurrent workers cannot each spend the same remaining byte budget,
	// matching internal/diagnostics.Fetcher.Inspect.
	select {
	case f.downloadSlot <- struct{}{}:
		defer func() { <-f.downloadSlot }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if exhausted, message := f.bytesExhausted(); exhausted {
		return nil, fmt.Errorf("%w: %s", ErrBudgetExhausted, message)
	}
	remaining := f.remainingBytes()

	path := fmt.Sprintf("repos/%s/%s/code-scanning/analyses/%d",
		url.PathEscape(org), url.PathEscape(repo), analysisID)

	body, err := f.client.GetSARIFLimited(ctx, path, remaining)
	if err != nil {
		if errors.Is(err, ghapi.ErrResponseTooLarge) {
			f.bytesRead.Store(f.limits.MaxBytes)
			return nil, fmt.Errorf("%w: SARIF exceeds the remaining byte budget; raise --deep-diagnostics-max-sarif-mb",
				ErrBudgetExhausted)
		}
		if ghapi.IsNotFound(err) {
			return nil, fmt.Errorf("analysis SARIF is unavailable, likely expired: %w", err)
		}
		if ghapi.IsForbidden(err) {
			return nil, fmt.Errorf("access to analysis SARIF is denied: %w", err)
		}
		return nil, err
	}
	f.bytesRead.Add(int64(len(body)))

	return Parse(body)
}

// document is the minimal SARIF shape this package reads. Every field it
// omits (message, locations, snippets, ...) is deliberate: this tool must
// never retain result text or source excerpts.
type document struct {
	Runs []run `json:"runs"`
}

type run struct {
	Tool      tool       `json:"tool"`
	Artifacts []struct{} `json:"artifacts"`
	Results   []result   `json:"results"`
}

type tool struct {
	Driver     component   `json:"driver"`
	Extensions []component `json:"extensions"`
}

type component struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	SemanticVersion string `json:"semanticVersion"`
	Rules           []struct {
		ID string `json:"id"`
	} `json:"rules"`
}

type result struct {
	RuleID string `json:"ruleId"`
	Level  string `json:"level"`
}

// defaultLevel is the SARIF-defined level when a result omits one.
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/ says the default depends on
// the rule's configuration, but absent that context "warning" is CodeQL's own
// default severity.
const defaultLevel = "warning"

// packPrefixLanguages maps a codeql/<x>-queries pack name segment to the
// canonical language, reusing the same names the analyses category and
// default setup APIs use wherever they overlap with model.NormalizeLanguage.
var packPrefixLanguages = map[string]model.Language{
	"java":       model.LangJavaKotlin,
	"kotlin":     model.LangJavaKotlin,
	"cpp":        model.LangCCpp,
	"csharp":     model.LangCSharp,
	"python":     model.LangPython,
	"javascript": model.LangJavaScriptTypeScript,
	"ruby":       model.LangRuby,
	"go":         model.LangGo,
	"rust":       model.LangRust,
	"swift":      model.LangSwift,
	"actions":    model.LangActions,
}

// rulePrefixLanguages maps a rule ID's leading path segment (its query
// language directory) to the canonical language. These are CodeQL query
// naming conventions, distinct from the Linguist/default-setup names in
// model.NormalizeLanguage, which is why they are kept local to this package.
var rulePrefixLanguages = map[string]model.Language{
	"java":    model.LangJavaKotlin,
	"cpp":     model.LangCCpp,
	"cs":      model.LangCSharp,
	"py":      model.LangPython,
	"js":      model.LangJavaScriptTypeScript,
	"rb":      model.LangRuby,
	"go":      model.LangGo,
	"rust":    model.LangRust,
	"swift":   model.LangSwift,
	"actions": model.LangActions,
}

// Parse extracts structural evidence from a SARIF document. It is exported so
// the extraction can be tested against recorded fixtures without any network
// access.
func Parse(body []byte) (*Result, error) {
	var doc document
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decoding SARIF: %w", err)
	}
	if len(doc.Runs) == 0 {
		return &Result{ResultsByLevel: map[string]int{}}, nil
	}
	// A code scanning analysis's SARIF has exactly one run.
	run := doc.Runs[0]

	result := &Result{
		CodeQLVersion:  coalesce(run.Tool.Driver.SemanticVersion, run.Tool.Driver.Version),
		ResultsByLevel: map[string]int{},
		ArtifactCount:  len(run.Artifacts),
	}

	ruleIDs := map[string]bool{}
	for _, id := range run.Tool.Driver.Rules {
		if id.ID != "" {
			ruleIDs[id.ID] = true
		}
	}

	var packs []string
	for _, extension := range run.Tool.Extensions {
		if extension.Name != "" {
			label := extension.Name
			if extension.Version != "" {
				label += "@" + extension.Version
			}
			packs = append(packs, label)
		}
		for _, id := range extension.Rules {
			if id.ID != "" {
				ruleIDs[id.ID] = true
			}
		}
	}
	sort.Strings(packs)
	result.QueryPacks = packs
	result.RuleCount = len(ruleIDs)

	result.Language = inferLanguage(run, ruleIDs)

	for _, item := range run.Results {
		level := item.Level
		if level == "" {
			level = defaultLevel
		}
		result.ResultsByLevel[level]++
	}

	return result, nil
}

// inferLanguage determines the language CodeQL actually scanned from tool
// evidence rather than from the caller-supplied analysis category, preferring
// the query pack names and falling back to rule ID prefixes when packs are
// unavailable (for example a minimal or hand-built SARIF document).
func inferLanguage(run run, ruleIDs map[string]bool) model.Language {
	for _, extension := range run.Tool.Extensions {
		if lang, ok := languageFromPackName(extension.Name); ok {
			return lang
		}
	}
	for id := range ruleIDs {
		if lang, ok := languageFromRuleID(id); ok {
			return lang
		}
	}
	return ""
}

// languageFromPackName extracts the language segment from a query pack name
// such as "codeql/java-queries" or "octo-org/csharp-extra-queries".
func languageFromPackName(name string) (model.Language, bool) {
	segment := name
	if slash := strings.LastIndex(segment, "/"); slash >= 0 {
		segment = segment[slash+1:]
	}
	segment = strings.TrimSuffix(segment, "-queries")
	lang, ok := packPrefixLanguages[segment]
	return lang, ok
}

// languageFromRuleID extracts the language segment from a rule ID such as
// "java/unused-import" or "cpp/path-injection".
func languageFromRuleID(id string) (model.Language, bool) {
	prefix := id
	if slash := strings.Index(prefix, "/"); slash >= 0 {
		prefix = prefix[:slash]
	} else {
		return "", false
	}
	lang, ok := rulePrefixLanguages[prefix]
	return lang, ok
}

func coalesce(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
