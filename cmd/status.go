package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cli/go-gh/v2/pkg/term"
	"github.com/spf13/cobra"

	"github.com/advanced-security/gh-ghas-audit/internal/cache"
	"github.com/advanced-security/gh-ghas-audit/internal/collector"
	"github.com/advanced-security/gh-ghas-audit/internal/diagnostics"
	"github.com/advanced-security/gh-ghas-audit/internal/ghapi"
	"github.com/advanced-security/gh-ghas-audit/internal/model"
	"github.com/advanced-security/gh-ghas-audit/internal/output"
)

// ExitCodeFailOn is returned when --fail-on matches, so scheduled workflows
// can distinguish a policy failure from a tool error.
const ExitCodeFailOn = 2

// statusOptions holds every flag for the status command.
type statusOptions struct {
	enterprise string
	format     string
	outputPath string

	staleAfter      string
	properties      []string
	groupByProperty string
	propertyFilters []string

	statusFilter     []string
	languageFilter   []string
	visibilityFilter []string
	nameFilter       []string
	excludeFilter    []string

	concurrency int
	cacheDir    string
	noCache     bool
	refresh     bool
	cacheMaxAge string

	failOn []string

	deepDiagnostics    string
	deepMaxRepos       int
	deepMaxMegabytes   int
	detailed           bool
	quiet              bool
	includeUnsupported bool
}

var statusOpts statusOptions

var codeScanningStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Report code scanning health across organizations and enterprises",
	Long: `Report code scanning health across organizations and enterprises.

Reports whether CodeQL default setup is configured, whether analysis runs are
actually succeeding, when each repository last scanned successfully, and which
languages are configured but not being analyzed.

Status is reported across four independent dimensions, because a single
pass or fail hides the problems customers care about:

  configuration  is code scanning set up, and did the security configuration attach
  execution      did the most recent analysis run succeed, fail, or never run
  freshness      how long ago the last successful analysis completed
  coverage       are all supported languages actually being analyzed

Examples:
  # One organization, human-readable summary
  gh ghas-audit code-scanning status --organization my-org

  # A whole enterprise, exported for reporting
  gh ghas-audit code-scanning status --enterprise my-enterprise --format csv --output status.csv

  # Only the repositories that need attention, grouped by application
  gh ghas-audit code-scanning status --organization my-org \
    --status failing,stalled,stale --group-by-property application

  # Per-language coverage gaps
  gh ghas-audit code-scanning status --organization my-org --format language-csv --output languages.csv

  # Fail a scheduled workflow when anything is broken
  gh ghas-audit code-scanning status --organization my-org --fail-on failing,stalled`,
	RunE: runCodeScanningStatus,
}

func init() {
	flags := codeScanningStatusCmd.Flags()

	flags.StringVarP(&statusOpts.enterprise, "enterprise", "e", "",
		"Enterprise slug to scan; expands to every organization in the enterprise")
	flags.StringVar(&statusOpts.format, "format", "table",
		"Output format: table, json, ndjson, csv or language-csv")
	flags.StringVar(&statusOpts.outputPath, "output", "",
		"Write output to a file instead of stdout")

	flags.StringVar(&statusOpts.staleAfter, "stale-after", "8d",
		"Age after which a successful scan is considered stale (default setup runs weekly, so this allows a one day buffer)")

	flags.StringSliceVar(&statusOpts.properties, "property", nil,
		"Custom property to include as a column (repeatable)")
	flags.StringVar(&statusOpts.groupByProperty, "group-by-property", "",
		"Group summary counts by a custom property, such as an application name")
	flags.StringSliceVar(&statusOpts.propertyFilters, "property-filter", nil,
		"Only include repositories whose custom property matches, as NAME=VALUE (repeatable, supports * wildcards)")

	flags.StringSliceVar(&statusOpts.statusFilter, "status", nil,
		"Only report repositories with these overall statuses (repeatable)")
	flags.StringSliceVar(&statusOpts.languageFilter, "language", nil,
		"Only report repositories involving these CodeQL languages (repeatable)")
	flags.StringSliceVar(&statusOpts.visibilityFilter, "visibility", nil,
		"Only scan repositories with these visibilities: public, private, internal")
	flags.StringSliceVar(&statusOpts.nameFilter, "match", nil,
		"Only scan repositories whose name matches these glob patterns (repeatable)")
	flags.StringSliceVar(&statusOpts.excludeFilter, "exclude", nil,
		"Skip repositories whose name matches these glob patterns (repeatable)")

	flags.IntVar(&statusOpts.concurrency, "concurrency", 8,
		"Maximum concurrent API requests; higher values scan faster but risk secondary rate limits")

	flags.StringVar(&statusOpts.cacheDir, "cache-dir", "",
		"Directory for the conditional request cache; defaults to the user cache directory")
	flags.BoolVar(&statusOpts.noCache, "no-cache", false,
		"Disable the conditional request cache")
	flags.BoolVar(&statusOpts.refresh, "refresh", false,
		"Discard cached responses before scanning")
	flags.StringVar(&statusOpts.cacheMaxAge, "cache-max-age", "",
		"Ignore cached responses older than this, for example 24h")

	flags.StringSliceVar(&statusOpts.failOn, "fail-on", nil,
		"Exit with code 2 when any repository has one of these statuses, for use in scheduled workflows")

	flags.StringVar(&statusOpts.deepDiagnostics, "deep-diagnostics", "",
		"Download and parse Actions logs for extra detail: 'problematic' or 'all'. Slow, best effort, and rate limit heavy")
	flags.IntVar(&statusOpts.deepMaxRepos, "deep-diagnostics-max-repos", 200,
		"Maximum repositories to inspect when --deep-diagnostics is enabled")
	flags.IntVar(&statusOpts.deepMaxMegabytes, "deep-diagnostics-max-mb", 32,
		"Maximum megabytes of logs to download when --deep-diagnostics is enabled")

	flags.BoolVar(&statusOpts.detailed, "detailed", false,
		"Add a detail column explaining why each repository has its status")
	flags.BoolVar(&statusOpts.quiet, "quiet", false,
		"Suppress progress output")

	codeScanningAuditCmd.AddCommand(codeScanningStatusCmd)
}

func runCodeScanningStatus(cmd *cobra.Command, _ []string) error {
	// Flags parsed successfully, so any later failure is a runtime problem
	// rather than a usage error and should not print the whole flag list.
	cmd.SilenceUsage = true

	format, err := output.ParseFormat(statusOpts.format)
	if err != nil {
		return err
	}

	staleAfter, err := parseDuration(statusOpts.staleAfter)
	if err != nil {
		return fmt.Errorf("invalid --stale-after: %w", err)
	}

	statusFilter, err := parseSeverities(statusOpts.statusFilter, "--status")
	if err != nil {
		return err
	}
	failOn, err := parseSeverities(statusOpts.failOn, "--fail-on")
	if err != nil {
		return err
	}
	languageFilter, err := parseLanguages(statusOpts.languageFilter)
	if err != nil {
		return err
	}
	propertyFilters, err := parsePropertyFilters(statusOpts.propertyFilters)
	if err != nil {
		return err
	}
	deepMode, err := parseDeepDiagnostics(statusOpts.deepDiagnostics)
	if err != nil {
		return err
	}

	organizations := splitList(Organizations)
	if statusOpts.enterprise == "" && len(organizations) == 0 && Repository == "" {
		return errors.New("specify --organization, --enterprise or --repository")
	}

	store, err := buildCache()
	if err != nil {
		return err
	}
	if statusOpts.refresh {
		if err := store.Clear(); err != nil {
			return fmt.Errorf("clearing cache: %w", err)
		}
	}

	client, err := ghapi.NewClient(ghapi.Options{
		Cache:       store,
		Concurrency: statusOpts.concurrency,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	progress := func(message string) {
		if !statusOpts.quiet {
			fmt.Fprintln(os.Stderr, message)
		}
	}

	options := collector.Options{
		Enterprise:            statusOpts.enterprise,
		Organizations:         organizations,
		Repository:            Repository,
		SkipArchived:          SkipArchived,
		SkipForks:             SkipForks,
		SecurityConfiguration: SecurityConfiguration,
		StaleAfter:            staleAfter,
		Concurrency:           statusOpts.concurrency,
		Properties:            statusOpts.properties,
		GroupByProperty:       statusOpts.groupByProperty,
		PropertyFilters:       propertyFilters,
		VisibilityFilter:      lowerAll(statusOpts.visibilityFilter),
		NameFilter:            statusOpts.nameFilter,
		ExcludeFilter:         statusOpts.excludeFilter,
		DeepDiagnostics:       deepMode,
		Progress:              progress,
	}

	if deepMode != collector.DeepDiagnosticsOff {
		progress("Deep diagnostics enabled: Actions logs will be downloaded and parsed. " +
			"This is best effort, considerably slower, and consumes significant rate limit budget.")
		options.LogFetcher = diagnostics.NewFetcher(client, diagnostics.Limits{
			MaxRepositories: statusOpts.deepMaxRepos,
			MaxBytes:        int64(statusOpts.deepMaxMegabytes) << 20,
		})
	}

	report, err := collector.New(client, options).Collect(ctx, version())
	if err != nil {
		return err
	}

	if err := store.Save(); err != nil {
		progress(fmt.Sprintf("warning: cache could not be saved: %v", err))
	}

	applyFilters(report, statusFilter, languageFilter, statusOpts.groupByProperty)

	if err := writeReport(report, format); err != nil {
		return err
	}

	if triggered := matchedSeverities(report, failOn); len(triggered) > 0 {
		fmt.Fprintf(os.Stderr, "\n--fail-on matched: %s\n", strings.Join(triggered, ", "))
		return &exitCodeError{code: ExitCodeFailOn}
	}

	return nil
}

// exitCodeError lets the command request a specific process exit code without
// printing a spurious error message.
type exitCodeError struct{ code int }

func (e *exitCodeError) Error() string { return "" }
func (e *exitCodeError) ExitCode() int { return e.code }

func buildCache() (*cache.Store, error) {
	if statusOpts.noCache {
		return cache.New(cache.Options{}), nil
	}

	dir := statusOpts.cacheDir
	if dir == "" {
		defaultDir, err := cache.DefaultDir()
		if err != nil {
			// A missing cache directory must never stop a scan.
			return cache.New(cache.Options{}), nil
		}
		dir = defaultDir
	}

	var maxAge time.Duration
	if statusOpts.cacheMaxAge != "" {
		parsed, err := parseDuration(statusOpts.cacheMaxAge)
		if err != nil {
			return nil, fmt.Errorf("invalid --cache-max-age: %w", err)
		}
		maxAge = parsed
	}

	store := cache.New(cache.Options{
		Dir:       filepath.Clean(dir),
		MaxAge:    maxAge,
		SchemaKey: model.SchemaVersion,
	})
	// Drop entries older than the configured maximum so the cache directory
	// does not grow without bound across scheduled runs.
	if err := store.Prune(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: cache could not be pruned: %v\n", err)
	}
	return store, nil
}

// applyFilters narrows the report to the requested statuses and languages and
// recomputes the summary, so displayed counts always match displayed rows.
func applyFilters(report *model.Report, severities []model.Severity, languages []model.Language, groupBy string) {
	if len(severities) == 0 && len(languages) == 0 {
		return
	}

	severitySet := map[model.Severity]bool{}
	for _, severity := range severities {
		severitySet[severity] = true
	}
	languageSet := map[model.Language]bool{}
	for _, language := range languages {
		languageSet[language] = true
	}

	filtered := report.Repositories[:0]
	for _, repo := range report.Repositories {
		if len(severitySet) > 0 && !severitySet[repo.Status.Overall] {
			continue
		}
		if len(languageSet) > 0 && !repoHasLanguage(repo, languageSet) {
			continue
		}
		filtered = append(filtered, repo)
	}

	report.Repositories = filtered
	report.Summary = model.BuildSummary(report.Repositories, groupBy)
	report.Organizations = model.BuildOrgReports(report.Repositories)
}

func repoHasLanguage(repo model.Repo, wanted map[model.Language]bool) bool {
	for _, state := range repo.Languages {
		if wanted[state.Language] {
			return true
		}
	}
	for _, language := range repo.DetectedLanguages {
		if wanted[language] {
			return true
		}
	}
	return false
}

func matchedSeverities(report *model.Report, failOn []model.Severity) []string {
	var matched []string
	for _, severity := range failOn {
		if count := report.Summary.BySeverity[string(severity)]; count > 0 {
			matched = append(matched, fmt.Sprintf("%s (%d)", severity, count))
		}
	}
	return matched
}

func writeReport(report *model.Report, format output.Format) error {
	writer := os.Stdout
	if statusOpts.outputPath != "" {
		file, err := os.Create(statusOpts.outputPath)
		if err != nil {
			return fmt.Errorf("creating %s: %w", statusOpts.outputPath, err)
		}
		defer func() { _ = file.Close() }()
		writer = file
	}

	// Table output only shows the properties the user asked for, because a
	// large organization can define many properties and the extra columns
	// make the terminal view unreadable. File formats include them all, where
	// extra columns cost nothing.
	tableProperties := statusOpts.properties
	if statusOpts.groupByProperty != "" && !contains(tableProperties, statusOpts.groupByProperty) {
		tableProperties = append(append([]string(nil), tableProperties...), statusOpts.groupByProperty)
	}

	fileProperties := statusOpts.properties
	if len(fileProperties) == 0 {
		fileProperties = output.PropertyColumns(report)
	}

	switch format {
	case output.FormatJSON:
		return output.WriteJSON(writer, report)
	case output.FormatNDJSON:
		return output.WriteNDJSON(writer, report)
	case output.FormatCSV:
		return output.WriteCSV(writer, report, fileProperties)
	case output.FormatLanguageCSV:
		return output.WriteLanguageCSV(writer, report, fileProperties)
	default:
		terminal := term.FromEnv()
		width, _, _ := terminal.Size()
		isTerminal := terminal.IsTerminalOutput() && statusOpts.outputPath == ""
		return output.WriteTable(writer, report, output.TableOptions{
			IsTerminal: isTerminal,
			Width:      width,
			Properties: tableProperties,
			Detailed:   statusOpts.detailed,
		})
	}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(value, wanted) {
			return true
		}
	}
	return false
}

var durationPattern = regexp.MustCompile(`^(\d+)\s*([dhms])$`)

// parseDuration accepts Go durations plus a day suffix, since scan freshness
// is naturally expressed in days.
func parseDuration(value string) (time.Duration, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return 0, errors.New("value is empty")
	}
	if match := durationPattern.FindStringSubmatch(value); match != nil {
		amount, err := strconv.Atoi(match[1])
		if err != nil {
			return 0, err
		}
		switch match[2] {
		case "d":
			return time.Duration(amount) * 24 * time.Hour, nil
		case "h":
			return time.Duration(amount) * time.Hour, nil
		case "m":
			return time.Duration(amount) * time.Minute, nil
		case "s":
			return time.Duration(amount) * time.Second, nil
		}
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("expected a duration such as 8d, 24h or 90m, got %q", value)
	}
	return parsed, nil
}

func parseSeverities(values []string, flagName string) ([]model.Severity, error) {
	var severities []model.Severity
	for _, value := range splitList(strings.Join(values, ",")) {
		severity, ok := model.ParseSeverity(value)
		if !ok {
			return nil, fmt.Errorf("invalid %s value %q; expected one of %s",
				flagName, value, severityNames())
		}
		severities = append(severities, severity)
	}
	return severities, nil
}

func severityNames() string {
	names := make([]string, 0, len(model.AllSeverities()))
	for _, severity := range model.AllSeverities() {
		names = append(names, string(severity))
	}
	return strings.Join(names, ", ")
}

func parseLanguages(values []string) ([]model.Language, error) {
	var languages []model.Language
	for _, value := range splitList(strings.Join(values, ",")) {
		language, ok := model.NormalizeLanguage(value)
		if !ok {
			return nil, fmt.Errorf("unsupported --language value %q; CodeQL does not analyze this language", value)
		}
		languages = append(languages, language)
	}
	return languages, nil
}

func parsePropertyFilters(values []string) (map[string][]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	filters := map[string][]string{}
	for _, value := range values {
		name, wanted, found := strings.Cut(value, "=")
		name = strings.TrimSpace(name)
		if !found || name == "" {
			return nil, fmt.Errorf("invalid --property-filter %q; expected NAME=VALUE", value)
		}
		filters[name] = append(filters[name], splitList(wanted)...)
	}
	return filters, nil
}

func parseDeepDiagnostics(value string) (collector.DeepDiagnosticsMode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return collector.DeepDiagnosticsOff, nil
	case "problematic":
		return collector.DeepDiagnosticsProblematic, nil
	case "all":
		return collector.DeepDiagnosticsAll, nil
	default:
		return "", fmt.Errorf("invalid --deep-diagnostics value %q; expected 'problematic' or 'all'", value)
	}
}

func splitList(value string) []string {
	var result []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func lowerAll(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, strings.ToLower(strings.TrimSpace(value)))
	}
	return result
}
