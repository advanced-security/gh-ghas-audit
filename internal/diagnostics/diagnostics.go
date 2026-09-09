// Package diagnostics implements the opt-in, best-effort inspection of Actions
// logs used by --deep-diagnostics.
//
// GitHub does not expose code scanning tool status page warnings through any
// documented REST or GraphQL API. The only remaining source for messages such
// as extraction warnings or dependency resolution problems is the raw Actions
// log, which is unstructured, unversioned and can change at any time.
//
// To keep that best-effort inspection trustworthy, only genuine Actions
// annotations are considered. Analysis logs contain megabytes of configuration
// dumps and query evaluation traces that mention words like "warning",
// "dependency" and "analysis quality" during entirely healthy runs, so
// scanning raw log text produces false positives. Annotations are the same
// lines GitHub surfaces in the Actions user interface.
//
// Everything produced here is attributed to log parsing and is never presented
// as authoritative tool status.
package diagnostics

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/advanced-security/gh-ghas-audit/internal/ghapi"
	"github.com/advanced-security/gh-ghas-audit/internal/model"
)

// Defaults chosen to keep an opt-in diagnostic pass bounded even when a user
// points it at a large estate.
const (
	defaultMaxRepositories = 200
	defaultMaxBytes        = 32 << 20 // 32 MiB of compressed logs per run
	defaultMaxExcerpt      = 300
	maxDiagnosticsPerRun   = 25
	maxLineLength          = 16000
)

const (
	genericWarningCode = "analysis-warning"
	genericErrorCode   = "analysis-error"
)

// annotationPattern matches the Actions annotation markers that become
// warnings and errors in the run summary.
var annotationPattern = regexp.MustCompile(`##\[(warning|error)\](.*)$`)

// noisePatterns are annotations that say nothing about code scanning health.
// They appear on virtually every run and would otherwise mark healthy
// repositories as degraded.
var noisePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)codeql action v\d+ will be deprecated`),
	regexp.MustCompile(`(?i)node\.?js \d+ is deprecated`),
	regexp.MustCompile(`(?i)the (set-output|save-state|add-path|set-env) command is deprecated`),
	regexp.MustCompile(`(?i)this action is deprecated`),
	regexp.MustCompile(`(?i)please update all occurrences of the codeql action`),
	regexp.MustCompile(`(?i)^unexpected input\(s\)`),
	regexp.MustCompile(`(?i)cache (not found|save failed|restore failed)`),
}

// pattern describes a recognized annotation worth naming explicitly.
type pattern struct {
	code    string
	matcher *regexp.Regexp
	summary string
}

// knownPatterns name the problems customers report having to find by reading
// logs by hand. Annotations matching none of these are still reported, but
// under a generic code carrying their original text rather than an invented
// interpretation.
var knownPatterns = []pattern{
	{
		code:    "low-quality-scan",
		matcher: regexp.MustCompile(`(?i)(low[- ](\w+ )?analysis quality|quality of.{0,30}analysis|scan.{0,20}may be incomplete)`),
		summary: "CodeQL reported reduced analysis quality for this language",
	},
	{
		code: "dependency-extraction-failed",
		// Wording varies by ecosystem and CodeQL version. These are the forms
		// reported in customer feedback, such as "failed to extract dependency
		// information from build tool Gradle".
		matcher: regexp.MustCompile(`(?i)(fail\w*\s+to\s+extract\s+(a\s+|the\s+)?dependenc|` +
			`could\s+not\s+resolve\s+dependenc|` +
			`unable\s+to\s+(download|resolve|fetch)[^.\n]{0,40}dependenc|` +
			`dependency\s+(graph|information)[^.\n]{0,40}(fail|error|could not))`),
		summary: "CodeQL could not resolve project dependencies, which reduces analysis quality",
	},
	{
		code:    "build-failed",
		matcher: regexp.MustCompile(`(?i)(autobuild (failed|did not)|we were unable to automatically build|build (command )?failed)`),
		summary: "the automatic build step failed",
	},
	{
		code:    "no-code-found",
		matcher: regexp.MustCompile(`(?i)(no (source )?code (was )?(found|seen)|did not (see|find) any code|no supported (source )?code)`),
		summary: "CodeQL found no analyzable code for a configured language",
	},
	{
		code:    "language-auto-deselected",
		matcher: regexp.MustCompile(`(?i)(auto[- ]?deselect|disabling (the )?language|language.{0,20}was (disabled|removed))`),
		summary: "a language was automatically deselected from default setup",
	},
	{
		code:    "missing-api-hints",
		matcher: regexp.MustCompile(`(?i)(may not understand some (apis|libraries)|uncommon modules)`),
		summary: "CodeQL reported it may not understand some APIs used by this project",
	},
	{
		code:    "runner-unavailable",
		matcher: regexp.MustCompile(`(?i)(no runner (matching|available)|waiting for a runner.{0,40}(timed out|expired))`),
		summary: "no self-hosted runner matched the configured labels",
	},
	{
		code:    "registry-unreachable",
		matcher: regexp.MustCompile(`(?i)(connection test to .{0,80}failed|proxy.{0,30}(failed|unreachable)|could not connect to .{0,40}registry)`),
		summary: "CodeQL could not reach a configured package registry or proxy",
	},
}

// Fetcher downloads and inspects Actions logs within configured limits.
type Fetcher struct {
	client *ghapi.Client
	limits Limits

	inspected atomic.Int64
	bytesRead atomic.Int64
}

// Limits bounds the work a diagnostic pass may perform.
type Limits struct {
	// MaxRepositories caps how many repositories are inspected.
	MaxRepositories int
	// MaxBytes caps the total compressed log bytes downloaded.
	MaxBytes int64
	// MaxExcerpt caps the length of a retained log excerpt.
	MaxExcerpt int
}

// NewFetcher creates a Fetcher with sane defaults applied to zero values.
func NewFetcher(client *ghapi.Client, limits Limits) *Fetcher {
	if limits.MaxRepositories <= 0 {
		limits.MaxRepositories = defaultMaxRepositories
	}
	if limits.MaxBytes <= 0 {
		limits.MaxBytes = defaultMaxBytes
	}
	if limits.MaxExcerpt <= 0 {
		limits.MaxExcerpt = defaultMaxExcerpt
	}
	return &Fetcher{client: client, limits: limits}
}

// Budget reports whether the fetcher has exhausted its limits, and a message
// explaining which limit was reached.
func (f *Fetcher) Budget() (bool, string) {
	if f.inspected.Load() >= int64(f.limits.MaxRepositories) {
		return true, fmt.Sprintf(
			"deep diagnostics stopped after %d repositories; raise --deep-diagnostics-max-repos to inspect more",
			f.limits.MaxRepositories)
	}
	if f.bytesRead.Load() >= f.limits.MaxBytes {
		return true, fmt.Sprintf(
			"deep diagnostics stopped after downloading %d MiB of logs; raise --deep-diagnostics-max-mb to inspect more",
			f.limits.MaxBytes>>20)
	}
	return false, ""
}

// Inspect downloads the log archive for a run and returns any findings.
func (f *Fetcher) Inspect(ctx context.Context, org, repo string, runID int64) ([]model.Diagnostic, error) {
	if exhausted, _ := f.Budget(); exhausted {
		return nil, nil
	}
	f.inspected.Add(1)

	logPath := fmt.Sprintf("repos/%s/%s/actions/runs/%d/logs",
		url.PathEscape(org), url.PathEscape(repo), runID)

	archive, err := f.client.GetBytes(ctx, logPath)
	if err != nil {
		if ghapi.IsNotFound(err) || ghapi.IsForbidden(err) {
			// Logs expire and can be restricted. An absent archive is not a
			// failure worth stopping the scan for.
			return nil, nil
		}
		return nil, err
	}
	f.bytesRead.Add(int64(len(archive)))

	runURL := fmt.Sprintf("https://%s/%s/%s/actions/runs/%d", f.client.Host(), org, repo, runID)
	return Scan(archive, runURL, f.limits.MaxExcerpt)
}

// Scan extracts Actions annotations from a zipped log archive and classifies
// them. It is exported so the parsers can be tested against recorded log
// fixtures without any network access.
func Scan(archive []byte, runURL string, maxExcerpt int) ([]model.Diagnostic, error) {
	if len(archive) == 0 {
		return nil, nil
	}
	if maxExcerpt <= 0 {
		maxExcerpt = defaultMaxExcerpt
	}

	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, fmt.Errorf("reading log archive: %w", err)
	}

	seen := map[string]bool{}
	var diagnostics []model.Diagnostic

	for _, file := range reader.File {
		if len(diagnostics) >= maxDiagnosticsPerRun {
			break
		}
		if file.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(file.Name), ".txt") {
			continue
		}
		language, _ := model.NormalizeLanguage(languageFromLogPath(file.Name))

		opened, err := file.Open()
		if err != nil {
			continue
		}
		found := scanStream(opened, language, runURL, maxExcerpt, seen, len(diagnostics))
		_ = opened.Close()
		diagnostics = append(diagnostics, found...)
	}

	return diagnostics, nil
}

func scanStream(
	reader io.Reader,
	language model.Language,
	runURL string,
	maxExcerpt int,
	seen map[string]bool,
	already int,
) []model.Diagnostic {
	var diagnostics []model.Diagnostic

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineLength)

	for scanner.Scan() {
		if already+len(diagnostics) >= maxDiagnosticsPerRun {
			break
		}

		severity, message, ok := parseAnnotation(scanner.Text())
		if !ok || isNoise(message) {
			continue
		}

		code, summary := classifyAnnotation(message, severity)

		key := string(language) + "|" + code + "|" + summary
		if code == genericWarningCode || code == genericErrorCode {
			// Unrecognized annotations are keyed on their own text so that
			// two different problems are not collapsed into one entry.
			key = string(language) + "|" + code + "|" + message
		}
		if seen[key] {
			continue
		}
		seen[key] = true

		diagnostics = append(diagnostics, model.Diagnostic{
			Source:   model.SourceLog,
			Severity: severity,
			Code:     code,
			Language: language,
			Message:  summary,
			Excerpt:  truncate(message, maxExcerpt),
			URL:      runURL,
		})
	}

	return diagnostics
}

// parseAnnotation extracts the severity and text of an Actions annotation.
func parseAnnotation(line string) (string, string, bool) {
	match := annotationPattern.FindStringSubmatch(line)
	if match == nil {
		return "", "", false
	}
	message := strings.TrimSpace(match[2])
	if message == "" {
		return "", "", false
	}
	return match[1], message, true
}

func isNoise(message string) bool {
	for _, candidate := range noisePatterns {
		if candidate.MatchString(message) {
			return true
		}
	}
	return false
}

// classifyAnnotation names a recognized problem, or falls back to reporting
// the annotation verbatim rather than guessing at its meaning.
func classifyAnnotation(message, severity string) (string, string) {
	for _, candidate := range knownPatterns {
		if candidate.matcher.MatchString(message) {
			return candidate.code, candidate.summary
		}
	}
	if severity == "error" {
		return genericErrorCode, "the analysis run reported an error"
	}
	return genericWarningCode, "the analysis run reported a warning"
}

// languageFromLogPath recovers the analyzed language from an Actions log entry
// name such as "0_Analyze (java-kotlin).txt".
func languageFromLogPath(name string) string {
	open := strings.Index(name, "(")
	closing := strings.LastIndex(name, ")")
	if open < 0 || closing <= open {
		return ""
	}
	for _, token := range strings.Split(name[open+1:closing], ",") {
		token = strings.TrimSpace(token)
		if token != "" {
			return token
		}
	}
	return ""
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}
