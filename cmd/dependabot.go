package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cli/go-gh/v2/pkg/term"
	"github.com/spf13/cobra"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/cache"
	"github.com/advanced-security/gh-ghas-audit/v2/internal/collector"
	"github.com/advanced-security/gh-ghas-audit/v2/internal/ghapi"
	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
	"github.com/advanced-security/gh-ghas-audit/v2/internal/output"
)

type dependabotOptions struct {
	scope      *scopeOptions
	enterprise string
	format     string
	outputPath string

	statusFilter     []string
	visibilityFilter []string
	nameFilter       []string
	excludeFilter    []string

	concurrency int
	cacheDir    string
	noCache     bool
	refresh     bool
	cacheMaxAge string

	failOn []string

	scanDepth                    string
	dependencyReviewCheckPattern string

	detailed bool
	quiet    bool
	verbose  bool
}

func newDependabotCommand(scope *scopeOptions) *cobra.Command {
	opts := &dependabotOptions{scope: scope}
	cmd := &cobra.Command{
		Use:   "dependabot",
		Short: "Report Dependabot / dependency graph (SCA) health across organizations and enterprises",
		Long: `Audit whether the dependency graph, Dependabot alerts, version updates,
pull request health and dependency review enforcement are actually working,
not just enabled.

All depths use the same collector, filters, cache and output formats:
  config       configuration-only audit (no runtime health verdict)
  health       API-based health assessment (default)
  diagnostics  health plus a per-branch dependency review enforcement check

Examples:
  gh ghas-audit dependabot --organization my-org
  gh ghas-audit dependabot --enterprise my-enterprise --scan-depth config
  gh ghas-audit dependabot -r owner/repo --scan-depth diagnostics
  gh ghas-audit dependabot -o my-org --format csv --output report.csv
  gh ghas-audit dependabot -o my-org --fail-on failing,stalled`,
		Args: cobra.NoArgs,
		RunE: opts.run,
	}
	flags := cmd.Flags()

	flags.StringVarP(&opts.enterprise, "enterprise", "e", "",
		"Enterprise slug to scan; expands to every organization in the enterprise")
	flags.StringVar(&opts.format, "format", "table",
		"Output format: table, json, ndjson or csv")
	flags.StringVar(&opts.outputPath, "output", "",
		"Write output to a file instead of stdout")

	flags.StringSliceVar(&opts.statusFilter, "status", nil,
		"Only report repositories with these overall statuses (repeatable)")
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
	flags.StringVar(&opts.dependencyReviewCheckPattern, "dependency-review-check-pattern", "dependency review",
		"Case-insensitive substring matched against required status check names to detect dependency "+
			"review enforcement (only checked at --scan-depth diagnostics; there is no dedicated ruleset rule type)")

	flags.BoolVar(&opts.detailed, "detailed", false,
		"Add a detail column explaining why each repository has its status")
	flags.BoolVar(&opts.quiet, "quiet", false,
		"Suppress progress output")
	flags.BoolVar(&opts.verbose, "verbose", false,
		"Report every repository by name and status as it completes, instead of only a running count")

	return cmd
}

func (opts *dependabotOptions) run(cmd *cobra.Command, _ []string) error {
	cmd.SilenceUsage = true

	format, err := output.ParseFormat(opts.format)
	if err != nil {
		return err
	}
	if format == output.FormatLanguageCSV {
		return fmt.Errorf("--format language-csv is not supported by the dependabot command")
	}

	statusFilter, err := parseSeverities(opts.statusFilter, "--status")
	if err != nil {
		return err
	}
	failOn, err := parseSeverities(opts.failOn, "--fail-on")
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
	depth, err := parseDepth(opts.scanDepth)
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

	options := collector.DependabotOptions{
		Enterprise:                   opts.enterprise,
		Organizations:                organizations,
		Repository:                   opts.scope.repository,
		SkipArchived:                 opts.scope.skipArchived,
		SkipForks:                    opts.scope.skipForks,
		Concurrency:                  opts.concurrency,
		Match:                        opts.nameFilter,
		Exclude:                      opts.excludeFilter,
		VisibilityFilter:             visibilityFilter,
		Depth:                        depth,
		DependencyReviewCheckPattern: opts.dependencyReviewCheckPattern,
		Progress:                     progress,
		Verbose:                      opts.verbose,
	}

	report, err := collector.NewDependabotCollector(client, options).Collect(ctx, version())
	if err != nil {
		return err
	}
	report.Settings.Match = append([]string(nil), opts.nameFilter...)
	report.Settings.Exclude = append([]string(nil), opts.excludeFilter...)
	report.Settings.Visibility = append([]string(nil), visibilityFilter...)
	report.Settings.Status = append([]model.Severity(nil), statusFilter...)

	if err := store.Save(); err != nil {
		progress(fmt.Sprintf("warning: cache could not be saved: %v", err))
	}

	triggered := matchedDependabotSeverities(report, failOn)

	applyDependabotFilters(report, statusFilter)

	if err := opts.writeReport(cmd, report, format); err != nil {
		return err
	}

	if len(triggered) > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "\n--fail-on matched: %s\n", strings.Join(triggered, ", "))
		return &exitCodeError{code: ExitCodeFailOn}
	}

	return nil
}

func (opts *dependabotOptions) buildCache(warnings io.Writer) (*cache.Store, error) {
	if opts.noCache {
		return cache.New(cache.Options{}), nil
	}

	dir := opts.cacheDir
	if dir == "" {
		defaultDir, err := cache.DefaultDir()
		if err != nil {
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
		// A different cache directory keeps dependabot's cached responses
		// (dependabot.yml, alerts, PR status) from colliding with, or being
		// invalidated by, code scanning's differently-shaped cached entries.
		Dir:       filepath.Clean(filepath.Join(dir, "dependabot")),
		MaxAge:    maxAge,
		SchemaKey: model.DependabotSchemaVersion,
	})
	if err := store.Prune(); err != nil {
		fmt.Fprintf(warnings, "warning: cache could not be pruned: %v\n", err)
	}
	return store, nil
}

func matchedDependabotSeverities(report *model.DependabotReport, failOn []model.Severity) []string {
	if len(failOn) == 0 {
		return nil
	}
	set := map[model.Severity]bool{}
	for _, severity := range failOn {
		set[severity] = true
	}
	seen := map[model.Severity]bool{}
	var matched []string
	for _, repo := range report.Repositories {
		if set[repo.Status.Overall] && !seen[repo.Status.Overall] {
			seen[repo.Status.Overall] = true
			matched = append(matched, string(repo.Status.Overall))
		}
	}
	return matched
}

// applyDependabotFilters narrows the report to the requested statuses and
// recomputes the summary so displayed counts always match displayed rows.
func applyDependabotFilters(report *model.DependabotReport, severities []model.Severity) {
	if len(severities) == 0 {
		return
	}
	set := map[model.Severity]bool{}
	for _, severity := range severities {
		set[severity] = true
	}

	filtered := report.Repositories[:0]
	for _, repo := range report.Repositories {
		if set[repo.Status.Overall] {
			filtered = append(filtered, repo)
		}
	}
	report.Repositories = filtered
	report.Summary = model.BuildDependabotSummary(report.Repositories)
	rebuilt := model.BuildDependabotOrgReports(report.Repositories)
	report.Organizations = mergeDependabotOrgErrors(rebuilt, report.Organizations)
}

// mergeDependabotOrgErrors preserves organization-level scan errors across a
// filtered rebuild, mirroring code scanning's mergeOrgErrors.
func mergeDependabotOrgErrors(rebuilt []model.OrgReport, previous []model.OrgReport) []model.OrgReport {
	errorsByLogin := map[string]string{}
	for _, org := range previous {
		if org.Error != "" {
			errorsByLogin[org.Login] = org.Error
		}
	}
	seen := map[string]bool{}
	for i := range rebuilt {
		seen[rebuilt[i].Login] = true
	}
	for login, message := range errorsByLogin {
		if !seen[login] {
			rebuilt = append(rebuilt, model.OrgReport{Login: login, Error: message})
		}
	}
	return rebuilt
}

func (opts *dependabotOptions) writeReport(cmd *cobra.Command, report *model.DependabotReport, format output.Format) (err error) {
	writer := cmd.OutOrStdout()
	if opts.outputPath != "" {
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

	switch format {
	case output.FormatJSON:
		return output.WriteDependabotJSON(writer, report)
	case output.FormatNDJSON:
		return output.WriteDependabotNDJSON(writer, report)
	case output.FormatCSV:
		return output.WriteDependabotCSV(writer, report)
	default:
		terminal := term.FromEnv()
		width, _, _ := terminal.Size()
		isTerminal := terminal.IsTerminalOutput() && writer == os.Stdout
		return output.WriteDependabotTable(writer, report, output.TableOptions{
			IsTerminal: isTerminal,
			Width:      width,
			Detailed:   opts.detailed,
		})
	}
}
