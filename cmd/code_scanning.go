package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cli/go-gh/v2/pkg/term"
	"github.com/spf13/cobra"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/cache"
	"github.com/advanced-security/gh-ghas-audit/v2/internal/collector"
	"github.com/advanced-security/gh-ghas-audit/v2/internal/diagnostics"
	"github.com/advanced-security/gh-ghas-audit/v2/internal/ghapi"
	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
	"github.com/advanced-security/gh-ghas-audit/v2/internal/output"
)

// ExitCodeFailOn is returned when --fail-on matches, so scheduled workflows
// can distinguish a policy failure from a tool error.
const ExitCodeFailOn = 2

type codeScanningOptions struct {
	scope      *scopeOptions
	enterprise string
	format     string
	outputPath string

	staleAfter         string
	staleAfterInactive string
	inactiveAfter      string
	activityFilter     []string
	properties         []string
	groupByProperty    string
	propertyFilters    []string

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

	scanDepth        string
	deepScope        string
	deepDiagnostics  string
	deepMaxRepos     int
	deepMaxMegabytes int
	detailed         bool
	quiet            bool
}

func newCodeScanningCommand(scope *scopeOptions) *cobra.Command {
	opts := &codeScanningOptions{scope: scope}
	cmd := &cobra.Command{
		Use:   "code-scanning",
		Short: "Report code scanning health across organizations and enterprises",
		Long: `Audit CodeQL configuration, execution, freshness and language coverage.

All depths use the same collector, filters, cache and output formats:
  config       configuration-only audit (no runtime health verdict)
  health       API-based health assessment (default)
  diagnostics  health plus best-effort Actions log inspection

Examples:
  gh ghas-audit code-scanning --organization my-org
  gh ghas-audit code-scanning --enterprise my-enterprise --scan-depth config
  gh ghas-audit code-scanning -r owner/repo --scan-depth diagnostics --deep-scope all
  gh ghas-audit code-scanning -o my-org --format csv --output report.csv
  gh ghas-audit code-scanning -o my-org --fail-on failing,stalled`,
		Args: cobra.NoArgs,
		RunE: opts.run,
	}
	flags := cmd.Flags()

	flags.StringVarP(&opts.enterprise, "enterprise", "e", "",
		"Enterprise slug to scan; expands to every organization in the enterprise")
	flags.StringVar(&opts.format, "format", "table",
		"Output format: table, json, ndjson, csv or language-csv")
	flags.StringVar(&opts.outputPath, "output", "",
		"Write output to a file instead of stdout")

	flags.StringVar(&opts.staleAfter, "stale-after", "8d",
		"Scan freshness threshold for active repositories")
	flags.StringVar(&opts.staleAfterInactive, "stale-after-inactive", "32d",
		"Scan freshness threshold for inactive repositories")
	flags.StringVar(&opts.inactiveAfter, "inactive-after", "180d",
		"Time without a push or pull request update before a repository is inactive")
	flags.StringSliceVar(&opts.activityFilter, "activity", nil,
		"Only report repositories with this activity: active or inactive")

	flags.StringSliceVar(&opts.properties, "property", nil,
		"Custom property to include as a column (repeatable)")
	flags.StringVar(&opts.groupByProperty, "group-by-property", "",
		"Group summary counts by a custom property, such as an application name")
	flags.StringArrayVar(&opts.propertyFilters, "property-filter", nil,
		"Only include repositories whose custom property matches, as NAME=VALUE (repeatable, supports * wildcards)")

	flags.StringSliceVar(&opts.statusFilter, "status", nil,
		"Only report repositories with these overall statuses (repeatable)")
	flags.StringSliceVar(&opts.languageFilter, "language", nil,
		"Only report repositories involving these CodeQL languages (repeatable)")
	flags.StringSliceVar(&opts.visibilityFilter, "visibility", nil,
		"Only scan repositories with these visibilities: public, private, internal")
	flags.StringSliceVar(&opts.nameFilter, "match", nil,
		"Only scan repositories whose name matches these glob patterns (repeatable)")
	flags.StringSliceVar(&opts.excludeFilter, "exclude", nil,
		"Skip repositories whose name matches these glob patterns (repeatable)")

	flags.IntVar(&opts.concurrency, "concurrency", 8,
		"Maximum concurrent API requests; higher values scan faster but risk secondary rate limits")

	flags.StringVar(&opts.cacheDir, "cache-dir", "",
		"Directory for the conditional request cache; defaults to the user cache directory")
	flags.BoolVar(&opts.noCache, "no-cache", false,
		"Disable the conditional request cache")
	flags.BoolVar(&opts.refresh, "refresh", false,
		"Discard cached responses before scanning")
	flags.StringVar(&opts.cacheMaxAge, "cache-max-age", "",
		"Ignore cached responses older than this, for example 24h")

	flags.StringSliceVar(&opts.failOn, "fail-on", nil,
		"Exit with code 2 when any repository has one of these statuses, for use in scheduled workflows")

	flags.StringVar(&opts.scanDepth, "scan-depth", "health",
		"Evidence depth: config, health or diagnostics")
	flags.StringVar(&opts.deepScope, "deep-scope", "all",
		"Log selection at diagnostics depth: all or problematic (skips apparently healthy repositories)")

	flags.StringVar(&opts.deepDiagnostics, "deep-diagnostics", "",
		"Deprecated, use --scan-depth diagnostics with --deep-scope")
	_ = flags.MarkDeprecated("deep-diagnostics", "use --scan-depth diagnostics with --deep-scope")
	flags.IntVar(&opts.deepMaxRepos, "deep-diagnostics-max-repos", 200,
		"Maximum repositories to inspect at diagnostics depth")
	flags.IntVar(&opts.deepMaxMegabytes, "deep-diagnostics-max-mb", 32,
		"Total compressed log download budget in MiB")

	flags.BoolVar(&opts.detailed, "detailed", false,
		"Add a detail column explaining why each repository has its status")
	flags.BoolVar(&opts.quiet, "quiet", false,
		"Suppress progress output")

	return cmd
}

func (opts *codeScanningOptions) run(cmd *cobra.Command, _ []string) error {
	// Flags parsed successfully, so any later failure is a runtime problem
	// rather than a usage error and should not print the whole flag list.
	cmd.SilenceUsage = true

	format, err := output.ParseFormat(opts.format)
	if err != nil {
		return err
	}

	staleAfter, err := parseDuration(opts.staleAfter)
	if err != nil {
		return fmt.Errorf("invalid --stale-after: %w", err)
	}
	if staleAfter == 0 {
		return errors.New("invalid --stale-after: duration must be greater than zero")
	}
	staleAfterInactive, err := parseDuration(opts.staleAfterInactive)
	if err != nil {
		return fmt.Errorf("invalid --stale-after-inactive: %w", err)
	}
	if staleAfterInactive == 0 {
		return errors.New("invalid --stale-after-inactive: duration must be greater than zero")
	}
	inactiveAfter, err := parseDuration(opts.inactiveAfter)
	if err != nil {
		return fmt.Errorf("invalid --inactive-after: %w", err)
	}
	if inactiveAfter == 0 {
		return errors.New("invalid --inactive-after: duration must be greater than zero")
	}
	activityFilter, err := parseActivities(opts.activityFilter)
	if err != nil {
		return err
	}

	statusFilter, err := parseSeverities(opts.statusFilter, "--status")
	if err != nil {
		return err
	}
	failOn, err := parseSeverities(opts.failOn, "--fail-on")
	if err != nil {
		return err
	}
	languageFilter, err := parseLanguages(opts.languageFilter)
	if err != nil {
		return err
	}
	visibilityFilter, err := parseVisibilities(opts.visibilityFilter)
	if err != nil {
		return err
	}
	if err := validateGlobs(opts.nameFilter, "--match"); err != nil {
		return err
	}
	if err := validateGlobs(opts.excludeFilter, "--exclude"); err != nil {
		return err
	}
	propertyFilters, err := parsePropertyFilters(opts.propertyFilters)
	if err != nil {
		return err
	}
	depth, deepMode, err := resolveDepth(
		opts.scanDepth, opts.deepScope, opts.deepDiagnostics,
		cmd.Flags().Changed("scan-depth"))
	if err != nil {
		return err
	}

	organizations := splitList(opts.scope.organizations)
	if opts.scope.repository != "" && (len(organizations) > 0 || opts.enterprise != "") {
		return errors.New("--repository cannot be combined with --organization/--organizations or --enterprise")
	}
	if opts.enterprise == "" && len(organizations) == 0 && opts.scope.repository == "" {
		return errors.New("specify --organization, --enterprise or --repository")
	}
	if opts.concurrency < 1 {
		return errors.New("--concurrency must be at least 1")
	}
	if opts.deepMaxRepos < 1 || opts.deepMaxMegabytes < 1 {
		return errors.New("--deep-diagnostics-max-repos and --deep-diagnostics-max-mb must be at least 1")
	}
	if int64(opts.deepMaxMegabytes) > (1<<63-1)>>20 {
		return errors.New("--deep-diagnostics-max-mb is too large")
	}

	store, err := opts.buildCache(cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	if opts.refresh {
		if err := store.Clear(); err != nil {
			return fmt.Errorf("clearing cache: %w", err)
		}
	}

	client, err := ghapi.NewClient(ghapi.Options{
		Cache:       store,
		Concurrency: opts.concurrency,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	progress := func(message string) {
		if !opts.quiet {
			fmt.Fprintln(cmd.ErrOrStderr(), message)
		}
	}

	options := collector.Options{
		Enterprise:            opts.enterprise,
		Organizations:         organizations,
		Repository:            opts.scope.repository,
		SkipArchived:          opts.scope.skipArchived,
		SkipForks:             opts.scope.skipForks,
		SecurityConfiguration: opts.scope.securityConfiguration,
		StaleAfter:            staleAfter,
		StaleAfterInactive:    staleAfterInactive,
		InactiveAfter:         inactiveAfter,
		Concurrency:           opts.concurrency,
		Properties:            opts.properties,
		GroupByProperty:       opts.groupByProperty,
		PropertyFilters:       propertyFilters,
		VisibilityFilter:      visibilityFilter,
		NameFilter:            opts.nameFilter,
		ExcludeFilter:         opts.excludeFilter,
		Depth:                 depth,
		DeepDiagnostics:       deepMode,
		Progress:              progress,
	}

	if deepMode != collector.DeepDiagnosticsOff {
		progress("Deep diagnostics enabled: Actions logs will be downloaded and parsed. " +
			"This is best effort, considerably slower, and consumes significant rate limit budget.")
		options.LogFetcher = diagnostics.NewFetcher(client, diagnostics.Limits{
			MaxRepositories: opts.deepMaxRepos,
			MaxBytes:        int64(opts.deepMaxMegabytes) << 20,
		})
	}

	report, err := collector.New(client, options).Collect(ctx, version())
	if err != nil {
		return err
	}
	report.Settings.Match = append([]string(nil), opts.nameFilter...)
	report.Settings.Exclude = append([]string(nil), opts.excludeFilter...)
	report.Settings.Visibility = append([]string(nil), visibilityFilter...)
	report.Settings.PropertyFilters = clonePropertyFilters(propertyFilters)
	report.Settings.Status = append([]model.Severity(nil), statusFilter...)
	report.Settings.Language = append([]model.Language(nil), languageFilter...)
	report.Settings.Activity = append([]model.Activity(nil), activityFilter...)

	if err := store.Save(); err != nil {
		progress(fmt.Sprintf("warning: cache could not be saved: %v", err))
	}

	// --fail-on is a compliance gate on what was collected, not on what is
	// displayed. Evaluating it before the presentation filters stops
	// "--status healthy --fail-on failing" from exiting successfully while
	// failing repositories sit in scope.
	triggered := matchedSeverities(report, failOn)

	applyFilters(report, statusFilter, languageFilter, activityFilter, opts.groupByProperty)

	if err := opts.writeReport(cmd, report, format); err != nil {
		return err
	}

	if len(triggered) > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "\n--fail-on matched: %s\n", strings.Join(triggered, ", "))
		return &exitCodeError{code: ExitCodeFailOn}
	}

	return nil
}

// exitCodeError lets the command request a specific process exit code without
// printing a spurious error message.
type exitCodeError struct{ code int }

func (e *exitCodeError) Error() string { return "" }
func (e *exitCodeError) ExitCode() int { return e.code }

func (opts *codeScanningOptions) buildCache(warnings io.Writer) (*cache.Store, error) {
	if opts.noCache {
		return cache.New(cache.Options{}), nil
	}

	dir := opts.cacheDir
	if dir == "" {
		defaultDir, err := cache.DefaultDir()
		if err != nil {
			// A missing cache directory must never stop a scan.
			return cache.New(cache.Options{}), nil
		}
		dir = defaultDir
	}

	var maxAge time.Duration
	if opts.cacheMaxAge != "" {
		parsed, err := parseDuration(opts.cacheMaxAge)
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
		fmt.Fprintf(warnings, "warning: cache could not be pruned: %v\n", err)
	}
	return store, nil
}

// applyFilters narrows the report to the requested statuses, languages and
// activity, and recomputes the summary so displayed counts always match
// displayed rows.
func applyFilters(
	report *model.Report,
	severities []model.Severity,
	languages []model.Language,
	activities []model.Activity,
	groupBy string,
) {
	if len(severities) == 0 && len(languages) == 0 && len(activities) == 0 {
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
	activitySet := map[model.Activity]bool{}
	for _, activity := range activities {
		activitySet[activity] = true
	}

	filtered := report.Repositories[:0]
	for _, repo := range report.Repositories {
		if len(severitySet) > 0 && !severitySet[repo.Status.Overall] {
			continue
		}
		if len(languageSet) > 0 && !repoHasLanguage(repo, languageSet) {
			continue
		}
		if len(activitySet) > 0 && !activitySet[repo.Activity] {
			continue
		}
		filtered = append(filtered, repo)
	}

	report.Repositories = filtered
	report.Summary = model.BuildSummary(report.Repositories, groupBy)
	// Organizations that could not be inspected have no repositories to
	// rebuild from, so their error entries are carried across. Dropping them
	// would remove the record of which organization was unreadable while the
	// report still claims to be incomplete.
	report.Organizations = mergeOrgErrors(model.BuildOrgReports(report.Repositories), report.Organizations)
}

// mergeOrgErrors adds back any organization whose collection failed, keeping
// the merged list sorted by login.
func mergeOrgErrors(rebuilt []model.OrgReport, previous []model.OrgReport) []model.OrgReport {
	present := make(map[string]int, len(rebuilt))
	for index, org := range rebuilt {
		present[org.Login] = index
	}

	for _, org := range previous {
		if org.Error == "" {
			continue
		}
		if index, ok := present[org.Login]; ok {
			rebuilt[index].Error = org.Error
			continue
		}
		rebuilt = append(rebuilt, model.OrgReport{
			Login:      org.Login,
			BySeverity: map[string]int{},
			Error:      org.Error,
		})
	}

	sort.Slice(rebuilt, func(i, j int) bool { return rebuilt[i].Login < rebuilt[j].Login })
	return rebuilt
}

// parseActivities resolves user-supplied activity names.
func parseActivities(values []string) ([]model.Activity, error) {
	var activities []model.Activity
	for _, value := range splitList(strings.Join(values, ",")) {
		switch model.Activity(strings.ToLower(strings.TrimSpace(value))) {
		case model.ActivityActive:
			activities = append(activities, model.ActivityActive)
		case model.ActivityInactive:
			activities = append(activities, model.ActivityInactive)
		case model.ActivityUnknown:
			activities = append(activities, model.ActivityUnknown)
		default:
			return nil, fmt.Errorf("invalid --activity value %q; expected active, inactive or unknown", value)
		}
	}
	return activities, nil
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

func (opts *codeScanningOptions) writeReport(cmd *cobra.Command, report *model.Report, format output.Format) (err error) {
	writer := cmd.OutOrStdout()
	if opts.outputPath != "" {
		// A path that looks like a flag almost always means the intended
		// value was dropped by the shell, for example `--output $null` in
		// PowerShell, which would silently create a file named after the next
		// flag.
		if strings.HasPrefix(opts.outputPath, "-") {
			return fmt.Errorf(
				"--output %q looks like a flag rather than a file path; "+
					"if you meant to discard the output, omit --output or write to a temporary file",
				opts.outputPath)
		}
		var file *os.File
		file, err = os.Create(opts.outputPath)
		if err != nil {
			return fmt.Errorf("creating %s: %w", opts.outputPath, err)
		}
		defer func() {
			if closeErr := file.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("closing %s: %w", opts.outputPath, closeErr))
			}
		}()
		writer = file
	}

	// Table output only shows the properties the user asked for, because a
	// large organization can define many properties and the extra columns
	// make the terminal view unreadable. File formats include them all, where
	// extra columns cost nothing.
	tableProperties := opts.properties
	if opts.groupByProperty != "" && !contains(tableProperties, opts.groupByProperty) {
		tableProperties = append(append([]string(nil), tableProperties...), opts.groupByProperty)
	}

	fileProperties := output.ResolvePropertyColumns(report, opts.properties)

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
		isTerminal := terminal.IsTerminalOutput() && writer == os.Stdout
		return output.WriteTable(writer, report, output.TableOptions{
			IsTerminal: isTerminal,
			Width:      width,
			Properties: tableProperties,
			Detailed:   opts.detailed,
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
		amount, err := strconv.ParseInt(match[1], 10, 64)
		if err != nil {
			return 0, err
		}
		var unit time.Duration
		switch match[2] {
		case "d":
			unit = 24 * time.Hour
		case "h":
			unit = time.Hour
		case "m":
			unit = time.Minute
		case "s":
			unit = time.Second
		}
		const maxDuration = time.Duration(1<<63 - 1)
		if amount > int64(maxDuration/unit) {
			return 0, fmt.Errorf("duration %q exceeds the maximum supported duration", value)
		}
		return time.Duration(amount) * unit, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("expected a duration such as 8d, 24h or 90m, got %q", value)
	}
	if parsed < 0 {
		return 0, fmt.Errorf("duration must not be negative, got %q", value)
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

func parseVisibilities(values []string) ([]string, error) {
	values = lowerAll(splitList(strings.Join(values, ",")))
	for _, value := range values {
		switch value {
		case "public", "private", "internal":
		default:
			return nil, fmt.Errorf("invalid --visibility value %q; expected public, private or internal", value)
		}
	}
	return values, nil
}

func validateGlobs(patterns []string, flagName string) error {
	for _, pattern := range patterns {
		if _, err := path.Match(strings.ToLower(strings.TrimSpace(pattern)), ""); err != nil {
			return fmt.Errorf("invalid %s pattern %q: %w", flagName, pattern, err)
		}
	}
	return nil
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
		patterns := splitList(wanted)
		if len(patterns) == 0 {
			return nil, fmt.Errorf("invalid --property-filter %q; VALUE must not be empty", value)
		}
		if err := validateGlobs(patterns, "--property-filter"); err != nil {
			return nil, err
		}
		key := name
		for existing := range filters {
			if strings.EqualFold(existing, name) {
				key = existing
				break
			}
		}
		filters[key] = append(filters[key], patterns...)
	}
	return filters, nil
}

func clonePropertyFilters(filters map[string][]string) map[string][]string {
	if len(filters) == 0 {
		return nil
	}
	cloned := make(map[string][]string, len(filters))
	for name, values := range filters {
		cloned[name] = append([]string(nil), values...)
	}
	return cloned
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
		return "", fmt.Errorf("invalid value %q; expected 'problematic' or 'all'", value)
	}
}

// parseDepth resolves the scan depth. The dial words are accepted as aliases
// because they are the first thing people reach for, but the named values are
// canonical since they say what is gathered and what it costs.
func parseDepth(value string) (collector.Depth, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "health", "medium", "med":
		return collector.DepthHealth, nil
	case "config", "configuration", "low":
		return collector.DepthConfig, nil
	case "diagnostics", "diagnostic", "high", "deep":
		return collector.DepthDiagnostics, nil
	default:
		return "", fmt.Errorf("invalid --scan-depth value %q; expected 'config', 'health' or 'diagnostics'", value)
	}
}

// resolveDepth combines the scan depth, the deep scope and the deprecated
// --deep-diagnostics flag into a single decision.
//
// Log inspection defaults to every repository, because restricting it to
// repositories that already look unhealthy can only explain a bad verdict and
// never discover one: a warning hidden behind a green run is invisible to it.
func resolveDepth(depthValue, scopeValue, legacyValue string, depthExplicit bool) (collector.Depth, collector.DeepDiagnosticsMode, error) {
	depth, err := parseDepth(depthValue)
	if err != nil {
		return "", "", err
	}

	// The deprecated flag still selects diagnostics depth and its own scope,
	// so existing invocations keep working. Combining it with an explicit
	// lower depth is contradictory, and silently choosing the expensive one
	// would be the wrong way to resolve it.
	if strings.TrimSpace(legacyValue) != "" {
		if depthExplicit && depth != collector.DepthDiagnostics {
			return "", "", fmt.Errorf(
				"--deep-diagnostics implies --scan-depth diagnostics, which conflicts with --scan-depth %s", depthValue)
		}
		mode, modeErr := parseDeepDiagnostics(legacyValue)
		if modeErr != nil {
			return "", "", fmt.Errorf("invalid --deep-diagnostics %w", modeErr)
		}
		return collector.DepthDiagnostics, mode, nil
	}

	if depth != collector.DepthDiagnostics {
		return depth, collector.DeepDiagnosticsOff, nil
	}

	scope, err := parseDeepDiagnostics(scopeValue)
	if err != nil {
		return "", "", fmt.Errorf("invalid --deep-scope %w", err)
	}
	if scope == collector.DeepDiagnosticsOff {
		scope = collector.DeepDiagnosticsAll
	}
	return depth, scope, nil
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
