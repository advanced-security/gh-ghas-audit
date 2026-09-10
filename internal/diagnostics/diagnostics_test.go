package diagnostics

import (
	"archive/zip"
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
)

// buildArchive produces a zipped log archive shaped like the one the Actions
// API returns, keyed by log file name.
func buildArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()

	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, content := range files {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatalf("creating archive entry: %v", err)
		}
		if _, err := entry.Write([]byte(content)); err != nil {
			t.Fatalf("writing archive entry: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("closing archive: %v", err)
	}
	return buffer.Bytes()
}

func scanArchive(t *testing.T, files map[string]string) []model.Diagnostic {
	t.Helper()
	found, err := Scan(buildArchive(t, files), "https://github.com/acme/app/actions/runs/1", 300)
	if err != nil {
		t.Fatalf("Scan returned an error: %v", err)
	}
	return found
}

// realHealthyLog reproduces the shape of an actual successful CodeQL run:
// extractor configuration dumps, query evaluation traces that mention
// "Low Java analysis quality" purely because the diagnostic query is being
// executed, and only deprecation annotations. None of this indicates a problem.
const realHealthyLog = `2026-09-05T14:34:17.1Z ##[group]Run github/codeql-action/init@v3
2026-09-05T14:34:18.2Z "extract_dependencies_as_source" : {
2026-09-05T14:34:18.3Z "title" : "Extract dependencies as source code",
2026-09-05T14:34:18.4Z "description" : "Controls the verbosity of the extractor. Supported levels are errors, warnings, info"
2026-09-05T14:34:19.1Z [66/80] Loaded /opt/hostedtoolcache/CodeQL/2.26.4/x64/codeql/qlpacks/codeql/java-queries/1.11.9/Telemetry/DatabaseQualityDiagnostics.qlx.
2026-09-05T14:34:19.2Z Starting evaluation of codeql/java-queries/Telemetry/DatabaseQualityDiagnostics.ql.
2026-09-05T14:34:19.3Z Interpreted diagnostic query "Low Java analysis quality" (java/diagnostic/database-quality) at path /home/runner/work/_temp/codeql_databases/java/results/DatabaseQualityDiagnostics.bqrs.
2026-09-05T14:34:20.1Z ##[warning]CodeQL Action v3 will be deprecated in December 2026. Please update all occurrences of the CodeQL Action in your workflow files to v4.
2026-09-05T14:34:20.2Z ##[warning]Node.js 20 is deprecated. The following actions target Node.js 20 but are being forced to run on Node.js 24: actions/checkout@v4
2026-09-05T14:34:21.0Z Analysis complete.
`

// A healthy run must produce no findings. The query evaluation trace mentions
// "Low Java analysis quality" on every run, so matching raw log text instead
// of annotations would mark every repository as degraded.
func TestHealthyRunProducesNoDiagnostics(t *testing.T) {
	found := scanArchive(t, map[string]string{
		"1_Analyze (java-kotlin).txt": realHealthyLog,
	})

	if len(found) != 0 {
		t.Fatalf("a healthy run must produce no diagnostics, got %+v", found)
	}
}

func TestDeprecationAnnotationsAreTreatedAsNoise(t *testing.T) {
	found := scanArchive(t, map[string]string{
		"0_Analyze (go).txt": "" +
			"2026-09-05T14:34:20Z ##[warning]CodeQL Action v3 will be deprecated in December 2026.\n" +
			"2026-09-05T14:34:21Z ##[warning]Node.js 20 is deprecated. The following actions target Node.js 20\n" +
			"2026-09-05T14:34:22Z ##[warning]The set-output command is deprecated\n",
	})

	if len(found) != 0 {
		t.Fatalf("deprecation notices say nothing about scan health, got %+v", found)
	}
}

func TestKnownProblemsAreNamed(t *testing.T) {
	// These are the messages quoted in customer feedback, so the patterns are
	// validated against real wording rather than invented text.
	cases := []struct {
		line string
		code string
	}{
		{"Java analysis failed to extract a dependency graph from gradle", "dependency-extraction-failed"},
		{"failed to extract dependency information from build tool Gradle", "dependency-extraction-failed"},
		{"We were unable to automatically build your code", "build-failed"},
		{"No source code was seen during the build", "no-code-found"},
	}

	for _, test := range cases {
		found := scanArchive(t, map[string]string{
			"0_Analyze (java-kotlin).txt": "2026-09-05T14:34:17Z ##[warning]" + test.line + "\n",
		})
		if len(found) != 1 {
			t.Errorf("Scan(%q) returned %d diagnostics, want 1", test.line, len(found))
			continue
		}
		if found[0].Code != test.code {
			t.Errorf("Scan(%q) code = %q, want %q", test.line, found[0].Code, test.code)
		}
		if found[0].Source != model.SourceLog {
			t.Errorf("Scan(%q) source = %q, want log so consumers know it is best effort", test.line, found[0].Source)
		}
		if !strings.Contains(found[0].Excerpt, strings.Fields(test.line)[0]) {
			t.Errorf("Scan(%q) excerpt = %q, want the original message", test.line, found[0].Excerpt)
		}
	}
}

// GitHub's tool status page reports private package registry use and
// build-mode "none" as suggestions while still saying the configuration is
// working as expected. Escalating them would make this report contradict the
// page it is meant to summarize.
func TestSuggestionsAreInformationalAndDoNotChangeTheVerdict(t *testing.T) {
	cases := []struct {
		line string
		code string
	}{
		{"Connection test to https://my.com/a failed: socket hang up", "private-registries"},
		{"Java extraction used private package registries", "private-registries"},
		{"Java was extracted with build-mode set to 'none'", "build-mode-none"},
		{"java analysis may not understand some apis defined in uncommon modules", "missing-api-hints"},
	}

	for _, test := range cases {
		found := scanArchive(t, map[string]string{
			"0_Analyze (java-kotlin).txt": "2026-09-05T14:34:17Z ##[warning]" + test.line + "\n",
		})
		if len(found) != 1 {
			t.Errorf("Scan(%q) returned %d diagnostics, want 1", test.line, len(found))
			continue
		}
		if found[0].Code != test.code {
			t.Errorf("Scan(%q) code = %q, want %q", test.line, found[0].Code, test.code)
		}
		if found[0].Severity != severityInfo {
			t.Errorf("Scan(%q) severity = %q, want info so a green tool status page is not contradicted",
				test.line, found[0].Severity)
		}
	}
}

// An unrecognized Actions warning is not evidence of a code scanning problem.
func TestUnrecognizedAnnotationsAreInformational(t *testing.T) {
	found := scanArchive(t, map[string]string{
		"0_Analyze (go).txt": "2026-09-05T14:34:17Z ##[error]Something entirely unfamiliar went wrong with widgets\n",
	})

	if len(found) != 1 {
		t.Fatalf("got %d diagnostics, want 1", len(found))
	}
	if found[0].Severity != severityInfo {
		t.Errorf("severity = %q, want info", found[0].Severity)
	}
	if !strings.Contains(found[0].Excerpt, "widgets") {
		t.Errorf("excerpt = %q, want the original annotation text", found[0].Excerpt)
	}
	if strings.Contains(found[0].Message, "widgets") {
		t.Error("the summary must not claim to interpret an unrecognized message")
	}
}

// Genuine failures must still be escalated.
func TestRealProblemsRemainWarningsOrErrors(t *testing.T) {
	cases := map[string]string{
		"We were unable to automatically build your code": severityError,
		// "No analyzable code" means the language produced nothing at all, so
		// it is an error rather than a warning.
		"No source code was seen during the build":                       severityError,
		"Java analysis failed to extract a dependency graph from gradle": severityWarning,
		"CodeQL detected a low-quality scan":                             severityWarning,
	}

	for line, wantSeverity := range cases {
		found := scanArchive(t, map[string]string{
			"0_Analyze (java-kotlin).txt": "2026-09-05T14:34:17Z ##[warning]" + line + "\n",
		})
		if len(found) != 1 {
			t.Errorf("Scan(%q) returned %d diagnostics, want 1", line, len(found))
			continue
		}
		if found[0].Severity != wantSeverity {
			t.Errorf("Scan(%q) severity = %q, want %q", line, found[0].Severity, wantSeverity)
		}
	}
}

// Real failure text captured from a repository whose CodeQL run failed. The
// explanation follows a long command line, so the excerpt must reach it.
const realFailureAnnotation = `Encountered a fatal error while running ` +
	`"/opt/hostedtoolcache/CodeQL/2.26.4/x64/codeql/codeql database finalize --finalize-dataset ` +
	`--threads=2 --ram=6913 /home/runner/work/_temp/codeql_databases/python". Exit code was 32 and ` +
	`last log line was: CodeQL detected code written in GitHub Actions, but not an actions database.`

func TestDatabaseFinalizeFailureIsNamedAndFullyQuoted(t *testing.T) {
	found := scanArchive(t, map[string]string{
		"0_Analyze (python).txt": "2026-09-05T14:34:17Z ##[error]" + realFailureAnnotation + "\n",
	})

	if len(found) != 1 {
		t.Fatalf("got %d diagnostics, want 1", len(found))
	}
	if found[0].Code != "database-finalize-failed" {
		t.Errorf("code = %q, want database-finalize-failed", found[0].Code)
	}
	if found[0].Severity != severityError {
		t.Errorf("severity = %q, want error", found[0].Severity)
	}
	// The exit code and the explanation after it are the parts a customer
	// cannot get anywhere else, so truncation must not cut them off.
	if !strings.Contains(found[0].Excerpt, "Exit code was 32") {
		t.Errorf("excerpt must include the exit code, got %q", found[0].Excerpt)
	}
	if !strings.Contains(found[0].Excerpt, "CodeQL detected code written in") {
		t.Errorf("excerpt must reach the explanation after the command line, got %q", found[0].Excerpt)
	}
}

// realDiagnosticGroups reproduces the CodeQL diagnostic blocks captured from a
// real analysis run. These blocks are what the repository tool status page
// displays, so parsing them is what lets this report agree with that page.
const realDiagnosticGroups = `2026-09-09T20:11:00.1Z ##[group]C# analysis with build-mode 'none' completed
2026-09-09T20:11:00.2Z * C# analysis with build-mode 'none' completed successfully.
2026-09-09T20:11:00.3Z ##[endgroup]
2026-09-09T20:11:01.1Z ##[group]Low C# analysis quality (1 result)
2026-09-09T20:11:01.2Z * Scanning C# code completed successfully, but the scan encountered issues. This may be caused by problems identifying dependencies or use of generated source code. Some metrics of the database quality are: Percentage of calls with call target: 64 % (threshold 85 %). Percentage of expressions with known type: 78 % (threshold 85 %).
2026-09-09T20:11:01.3Z ##[endgroup]
2026-09-09T20:11:02.1Z ##[group]C# was extracted with build-mode set to 'none' (1 result)
2026-09-09T20:11:02.2Z * C# was extracted with build-mode set to 'none'. This means that all C# source in the working directory will be scanned.
2026-09-09T20:11:02.3Z ##[endgroup]
`

const realJavaDiagnosticGroups = `2026-09-09T20:11:00.1Z ##[group]14 duplicate classes filtered out (1 result)
2026-09-09T20:11:00.2Z * 14 files defined a class that clashes with the fully-qualified name of another scanned class. This means that only one of each clashing pair will be scanned.
2026-09-09T20:11:00.3Z ##[endgroup]
2026-09-09T20:11:01.1Z ##[group]Java was extracted with build-mode set to 'none' (1 result)
2026-09-09T20:11:01.2Z * Java was extracted with build-mode set to 'none'.
2026-09-09T20:11:01.3Z ##[endgroup]
2026-09-09T20:11:02.1Z ##[group]Java analysis used the system default JDK (1 result)
2026-09-09T20:11:02.2Z * Java analysis used the system default JDK.
2026-09-09T20:11:02.3Z ##[endgroup]
`

// The tool status page for this run shows a warning and a suggestion per
// language. The report must reproduce both, with the same severity split.
func TestDiagnosticGroupsReproduceTheToolStatusPage(t *testing.T) {
	found := scanArchive(t, map[string]string{
		"Analyze (csharp)/6_Perform CodeQL Analysis.txt":      realDiagnosticGroups,
		"Analyze (java-kotlin)/6_Perform CodeQL Analysis.txt": realJavaDiagnosticGroups,
	})

	byMessage := map[string]model.Diagnostic{}
	for _, diagnostic := range found {
		byMessage[diagnostic.Message] = diagnostic
	}

	quality, ok := byMessage["Low C# analysis quality"]
	if !ok {
		t.Fatalf("expected the low analysis quality diagnostic, got %+v", byMessage)
	}
	if quality.Severity != severityWarning {
		t.Errorf("low analysis quality severity = %q, want warning", quality.Severity)
	}
	if quality.Language != model.LangCSharp {
		t.Errorf("low analysis quality language = %q, want csharp", quality.Language)
	}
	// The metrics are the actionable part and must survive into the excerpt.
	if !strings.Contains(quality.Excerpt, "64 %") || !strings.Contains(quality.Excerpt, "threshold 85 %") {
		t.Errorf("excerpt must keep the quality metrics, got %q", quality.Excerpt)
	}

	duplicates, ok := byMessage["14 duplicate classes filtered out"]
	if !ok {
		t.Fatalf("expected the duplicate classes diagnostic, got %+v", byMessage)
	}
	if duplicates.Severity != severityWarning {
		t.Errorf("duplicate classes severity = %q, want warning", duplicates.Severity)
	}
	if duplicates.Language != model.LangJavaKotlin {
		t.Errorf("duplicate classes language = %q, want java-kotlin", duplicates.Language)
	}

	// Build-mode notes are suggestions on the status page, not warnings.
	for _, message := range []string{
		"C# was extracted with build-mode set to 'none'",
		"Java was extracted with build-mode set to 'none'",
		"Java analysis used the system default JDK",
	} {
		diagnostic, ok := byMessage[message]
		if !ok {
			t.Errorf("expected diagnostic %q", message)
			continue
		}
		if diagnostic.Severity != severityInfo {
			t.Errorf("%q severity = %q, want info", message, diagnostic.Severity)
		}
	}
}

// The same diagnostics appear in both the per-language job log and the
// combined analysis step log, so they must be reported once.
func TestDiagnosticGroupsAreDeduplicatedAcrossLogFiles(t *testing.T) {
	found := scanArchive(t, map[string]string{
		"5_Analyze (csharp).txt":                         realDiagnosticGroups,
		"Analyze (csharp)/6_Perform CodeQL Analysis.txt": realDiagnosticGroups,
	})

	counts := map[string]int{}
	for _, diagnostic := range found {
		counts[diagnostic.Message]++
	}
	for message, count := range counts {
		if count != 1 {
			t.Errorf("diagnostic %q reported %d times, want once", message, count)
		}
	}
}

// Ordinary log grouping must not be mistaken for a CodeQL diagnostic.
func TestOrdinaryLogGroupsAreIgnored(t *testing.T) {
	found := scanArchive(t, map[string]string{
		"0_Analyze (go).txt": "" +
			"2026-09-09T20:11:00Z ##[group]Run github/codeql-action/init@v3\n" +
			"2026-09-09T20:11:00Z with:\n" +
			"2026-09-09T20:11:00Z   languages: go\n" +
			"2026-09-09T20:11:00Z ##[endgroup]\n",
	})

	if len(found) != 0 {
		t.Fatalf("ordinary log groups must not produce diagnostics, got %+v", found)
	}
}

// A diagnostic title that is not recognized must not turn a repository red.
func TestUnknownDiagnosticGroupsAreInformational(t *testing.T) {
	found := scanArchive(t, map[string]string{
		"0_Analyze (go).txt": "" +
			"2026-09-09T20:11:00Z ##[group]Some entirely new diagnostic (1 result)\n" +
			"2026-09-09T20:11:00Z * Details about the new diagnostic.\n" +
			"2026-09-09T20:11:00Z ##[endgroup]\n",
	})

	if len(found) != 1 {
		t.Fatalf("got %d diagnostics, want 1", len(found))
	}
	if found[0].Severity != severityInfo {
		t.Errorf("severity = %q, want info", found[0].Severity)
	}
	if found[0].Message != "Some entirely new diagnostic" {
		t.Errorf("message = %q, want the diagnostic title verbatim", found[0].Message)
	}
}

func TestMissingWorkflowFileIsNamed(t *testing.T) {
	line := "Unable to validate code scanning workflow: error: getWorkflow() failed: Error: " +
		"Expected to find a code scanning workflow file at " +
		"/home/runner/work/app/app/dynamic/github-code-scanning/codeql, but no such file existed."

	found := scanArchive(t, map[string]string{
		"0_Analyze (javascript-typescript).txt": "2026-09-05T14:34:17Z ##[warning]" + line + "\n",
	})

	if len(found) != 1 || found[0].Code != "workflow-file-missing" {
		t.Fatalf("got %+v, want a workflow-file-missing diagnostic", found)
	}
}

// Ordinary log text must never produce a finding, only annotations.
func TestNonAnnotationLinesAreIgnored(t *testing.T) {
	found := scanArchive(t, map[string]string{
		"0_Analyze (go).txt": "" +
			"2026-09-05T14:34:17Z autobuild failed to extract a dependency graph\n" +
			"2026-09-05T14:34:18Z No source code was seen during the build\n",
	})

	if len(found) != 0 {
		t.Fatalf("only annotations may produce findings, got %+v", found)
	}
}

func TestRepeatedAnnotationsAreDeduplicated(t *testing.T) {
	line := "2026-09-05T14:34:17Z ##[warning]No source code was seen during the build\n"
	found := scanArchive(t, map[string]string{
		"0_Analyze (python).txt": line + line + line,
	})

	if len(found) != 1 {
		t.Fatalf("repeated annotations must collapse into one diagnostic, got %d", len(found))
	}
}

func TestDiagnosticsAreSeparatedByLanguage(t *testing.T) {
	found := scanArchive(t, map[string]string{
		"0_Analyze (java-kotlin).txt": "2026-09-05T14:34:17Z ##[warning]autobuild failed\n",
		"1_Analyze (python).txt":      "2026-09-05T14:34:17Z ##[warning]autobuild failed\n",
	})

	if len(found) != 2 {
		t.Fatalf("each language must report its own diagnostic, got %d: %+v", len(found), found)
	}

	languages := map[model.Language]bool{}
	for _, diagnostic := range found {
		languages[diagnostic.Language] = true
	}
	if !languages[model.LangJavaKotlin] || !languages[model.LangPython] {
		t.Errorf("expected diagnostics for both languages, got %v", languages)
	}
}

func TestDistinctUnknownAnnotationsAreNotCollapsed(t *testing.T) {
	found := scanArchive(t, map[string]string{
		"0_Analyze (go).txt": "" +
			"2026-09-05T14:34:17Z ##[warning]First unfamiliar problem\n" +
			"2026-09-05T14:34:18Z ##[warning]Second unfamiliar problem\n",
	})

	if len(found) != 2 {
		t.Fatalf("different unknown annotations must be reported separately, got %d", len(found))
	}
}

func TestExcerptsAreTruncated(t *testing.T) {
	long := "2026-09-05T14:34:17Z ##[warning]autobuild failed " +
		string(bytes.Repeat([]byte("x"), 500)) + "\n"

	found, err := Scan(buildArchive(t, map[string]string{"0_Analyze (go).txt": long}),
		"https://github.com/acme/app/actions/runs/1", 50)
	if err != nil {
		t.Fatalf("Scan returned an error: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("got %d diagnostics, want 1", len(found))
	}
	if len(found[0].Excerpt) > 60 {
		t.Errorf("excerpt was not truncated, length %d", len(found[0].Excerpt))
	}
}

func TestFindingsAreCappedPerRun(t *testing.T) {
	var builder strings.Builder
	for index := 0; index < maxDiagnosticsPerRun*3; index++ {
		builder.WriteString(fmt.Sprintf("2026-09-05T14:34:17Z ##[warning]Unfamiliar problem number %d\n", index))
	}

	found := scanArchive(t, map[string]string{"0_Analyze (go).txt": builder.String()})
	if len(found) > maxDiagnosticsPerRun {
		t.Fatalf("got %d diagnostics, want at most %d", len(found), maxDiagnosticsPerRun)
	}
	if len(found) == 0 {
		t.Fatal("expected some diagnostics before the cap was reached")
	}
}

func TestScanHandlesEmptyAndInvalidArchives(t *testing.T) {
	if found, err := Scan(nil, "url", 200); err != nil || len(found) != 0 {
		t.Errorf("an empty archive must be ignored, got %v, %v", found, err)
	}
	if _, err := Scan([]byte("not a zip file"), "url", 200); err == nil {
		t.Error("a corrupt archive must be reported rather than silently ignored")
	}
}

func TestLanguageFromLogPath(t *testing.T) {
	cases := map[string]string{
		"0_Analyze (java-kotlin).txt":           "java-kotlin",
		"1_Analyze (go, ubuntu-latest).txt":     "go",
		"2_Analyze (javascript-typescript).txt": "javascript-typescript",
		"3_Setup job.txt":                       "",
	}
	for name, want := range cases {
		if got := languageFromLogPath(name); got != want {
			t.Errorf("languageFromLogPath(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestParseAnnotation(t *testing.T) {
	severity, message, ok := parseAnnotation("2026-09-05T14:34:17Z ##[warning]something happened")
	if !ok || severity != "warning" || message != "something happened" {
		t.Errorf("parseAnnotation = %q, %q, %v", severity, message, ok)
	}

	if _, _, ok := parseAnnotation("2026-09-05T14:34:17Z ##[group]Run something"); ok {
		t.Error("group markers are not annotations")
	}
	if _, _, ok := parseAnnotation("plain log line"); ok {
		t.Error("plain log lines are not annotations")
	}
	if _, _, ok := parseAnnotation("2026-09-05T14:34:17Z ##[warning]"); ok {
		t.Error("an empty annotation carries no information")
	}
}

func TestBudgetStopsAfterLimits(t *testing.T) {
	fetcher := NewFetcher(nil, Limits{MaxRepositories: 1, MaxBytes: 1024})

	if exhausted, _ := fetcher.Budget(); exhausted {
		t.Fatal("a fresh fetcher must have budget available")
	}

	fetcher.inspected.Add(1)
	exhausted, message := fetcher.Budget()
	if !exhausted {
		t.Fatal("the repository limit must stop further work")
	}
	if message == "" {
		t.Error("reaching a limit must be explained so the result is not mistaken for a clean scan")
	}
}

func TestNewFetcherAppliesDefaults(t *testing.T) {
	fetcher := NewFetcher(nil, Limits{})
	if fetcher.limits.MaxRepositories != defaultMaxRepositories ||
		fetcher.limits.MaxBytes != defaultMaxBytes ||
		fetcher.limits.MaxExcerpt != defaultMaxExcerpt {
		t.Fatalf("zero limits must fall back to defaults, got %+v", fetcher.limits)
	}
}
