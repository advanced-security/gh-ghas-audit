package output

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/cli/go-gh/v2/pkg/tableprinter"
	"github.com/fatih/color"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
)

// severityColor maps a severity onto a terminal colour so that problems are
// visually obvious in a long list.
func severityColor(severity model.Severity, isTerminal bool) *color.Color {
	switch severity {
	case model.SeverityFailing:
		return colorFor(isTerminal, color.FgRed, color.Bold)
	case model.SeverityStalled:
		return colorFor(isTerminal, color.FgRed)
	case model.SeverityStale:
		return colorFor(isTerminal, color.FgYellow, color.Bold)
	case model.SeverityDegraded:
		return colorFor(isTerminal, color.FgYellow)
	case model.SeverityInProgress:
		return colorFor(isTerminal, color.FgBlue)
	case model.SeverityHealthy:
		return colorFor(isTerminal, color.FgGreen)
	default:
		return colorFor(isTerminal, color.FgHiBlack)
	}
}

// TableOptions configures terminal rendering.
type TableOptions struct {
	IsTerminal bool
	Width      int
	// Properties are the custom property columns to include.
	Properties []string
	// Detailed adds per-repository reasons, which is useful when triaging a
	// filtered list rather than scanning a whole estate.
	Detailed bool
}

// colorFor builds a color bound to the caller's terminal decision. fatih/color
// otherwise decides from the process stdout, so writing a table to a file while
// attached to a terminal would embed ANSI escapes in the file.
func colorFor(isTerminal bool, attributes ...color.Attribute) *color.Color {
	value := color.New(attributes...)
	if isTerminal {
		value.EnableColor()
	} else {
		value.DisableColor()
	}
	return value
}

// WriteTable renders a summary followed by a repository table.
func WriteTable(writer io.Writer, report *model.Report, opts TableOptions) error {
	if err := writeSummary(writer, report, opts.IsTerminal); err != nil {
		return err
	}

	if len(report.Repositories) == 0 {
		if _, err := fmt.Fprintln(writer, "\nNo repositories matched the current scope and filters."); err != nil {
			return err
		}
		// The footer still has to run. It carries the warnings and the
		// incomplete-report notice, and without them a scan in which every
		// organization failed is indistinguishable from one that legitimately
		// matched nothing.
		return writeFooter(writer, report, opts.IsTerminal)
	}

	// The nonterminal printer discards write errors. A buffered writer keeps
	// the first failure so Flush reports it even when Render does not.
	buffered := bufio.NewWriter(writer)
	printer := tableprinter.New(buffered, opts.IsTerminal, opts.Width)
	headerColor := wrap(colorFor(opts.IsTerminal, color.FgHiWhite, color.Bold))

	// "HEALTH" rather than "STATUS" because the report exposes four distinct
	// status dimensions, and because organizations often define a custom
	// property literally named "status".
	headers := []string{"HEALTH", "REPOSITORY", "CONFIG", "EXECUTION", "LAST SCAN", "LANGUAGES"}
	for _, property := range opts.Properties {
		headers = append(headers, strings.ToUpper(property))
	}
	if opts.Detailed {
		headers = append(headers, "DETAIL")
	}
	for _, header := range headers {
		printer.AddField(header, tableprinter.WithColor(headerColor), tableprinter.WithTruncate(nil))
	}
	printer.EndRow()

	for _, repo := range report.Repositories {
		statusColor := wrap(severityColor(repo.Status.Overall, opts.IsTerminal))
		printer.AddField(string(repo.Status.Overall), tableprinter.WithColor(statusColor), tableprinter.WithTruncate(nil))
		printer.AddField(repo.FullName, tableprinter.WithTruncate(nil))
		printer.AddField(string(repo.Status.Configuration), tableprinter.WithTruncate(nil))
		printer.AddField(executionCell(repo), tableprinter.WithTruncate(nil))
		printer.AddField(lastScanCell(repo), tableprinter.WithTruncate(nil))
		printer.AddField(languageCell(repo), tableprinter.WithTruncate(nil))
		for _, property := range opts.Properties {
			value, _ := model.PropertyValue(repo.Properties, property)
			printer.AddField(value, tableprinter.WithTruncate(nil))
		}
		if opts.Detailed {
			printer.AddField(detailCell(repo), tableprinter.WithTruncate(nil))
		}
		printer.EndRow()
	}

	if err := printer.Render(); err != nil {
		return err
	}
	if err := buffered.Flush(); err != nil {
		return err
	}

	return writeFooter(writer, report, opts.IsTerminal)
}

func writeSummary(writer io.Writer, report *model.Report, isTerminal bool) error {
	bold := colorFor(isTerminal, color.Bold)
	scope := report.Scope.Repository
	if scope == "" && report.Scope.Enterprise != "" {
		scope = fmt.Sprintf("enterprise %s (%d organizations)", report.Scope.Enterprise, len(report.Scope.Organizations))
	}
	if scope == "" {
		scope = strings.Join(report.Scope.Organizations, ", ")
	}

	if _, err := fmt.Fprintf(writer, "\n%s\n", bold.Sprintf("Code scanning status: %s", scope)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "%d repositories, %s needing attention. Scans are stale after %s for active repositories",
		report.Summary.TotalRepositories,
		colorFor(isTerminal, attentionColor(report.Summary.NeedsAttention)).Sprintf("%d", report.Summary.NeedsAttention),
		report.Settings.StaleAfter); err != nil {
		return err
	}
	if report.Settings.StaleAfterInactive != "" {
		if _, err := fmt.Fprintf(writer, " and %s for inactive ones", report.Settings.StaleAfterInactive); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(writer); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(writer); err != nil {
		return err
	}
	for _, severity := range model.AllSeverities() {
		count := report.Summary.BySeverity[string(severity)]
		if count == 0 {
			continue
		}
		if _, err := fmt.Fprintf(writer, "  %-16s %s\n",
			string(severity),
			severityColor(severity, isTerminal).Sprintf("%d", count)); err != nil {
			return err
		}
	}

	if len(report.Summary.Groups) > 0 {
		// The label comes from the group records themselves so the heading is
		// correct even when a report is rendered from stored JSON whose
		// settings were produced by a different invocation.
		label := report.Summary.Groups[0].Property
		if label == "" {
			label = report.Settings.GroupByProperty
		}
		if label == "" {
			label = "group"
		}
		if _, err := fmt.Fprintf(writer, "\n%s\n", bold.Sprintf("By %s", label)); err != nil {
			return err
		}
		groups := report.Summary.Groups
		if len(groups) > 15 {
			groups = groups[:15]
		}
		for _, group := range groups {
			if _, err := fmt.Fprintf(writer, "  %-30s %3d repositories, %s needing attention\n",
				truncateLabel(group.Value, 30),
				group.Repositories,
				colorFor(isTerminal, attentionColor(group.NeedsAttention)).Sprintf("%d", group.NeedsAttention)); err != nil {
				return err
			}
		}
		if len(report.Summary.Groups) > len(groups) {
			if _, err := fmt.Fprintf(writer, "  ... and %d more groups\n", len(report.Summary.Groups)-len(groups)); err != nil {
				return err
			}
		}
	}

	_, err := fmt.Fprintln(writer)
	return err
}

func writeFooter(writer io.Writer, report *model.Report, isTerminal bool) error {
	if len(report.Warnings) > 0 {
		if _, err := fmt.Fprintf(writer, "\n%s\n", colorFor(isTerminal, color.FgYellow, color.Bold).Sprint("Warnings")); err != nil {
			return err
		}
		for _, warning := range report.Warnings {
			if _, err := fmt.Fprintf(writer, "  - %s\n", warning); err != nil {
				return err
			}
		}
	}

	if report.Stats.Incomplete {
		if _, err := fmt.Fprintf(writer, "\n%s\n", colorFor(isTerminal, color.FgYellow).Sprint(
			"This report is incomplete. Absence of a problem here does not prove absence of a problem.")); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintf(writer, "\n%d API requests, %d cached, %d GraphQL queries in %.1fs",
		report.Stats.APIRequests, report.Stats.CacheHits, report.Stats.GraphQLRequests, report.Stats.DurationSeconds); err != nil {
		return err
	}
	if report.Stats.RateLimitRemains > 0 {
		if _, err := fmt.Fprintf(writer, ", %d rate limit remaining", report.Stats.RateLimitRemains); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(writer)
	return err
}

func attentionColor(count int) color.Attribute {
	if count > 0 {
		return color.FgRed
	}
	return color.FgGreen
}

func executionCell(repo model.Repo) string {
	value := string(repo.Status.Execution)
	if repo.Status.Execution == model.ExecNotApplicable {
		return "-"
	}
	return value
}

func lastScanCell(repo model.Repo) string {
	if repo.LastSuccessfulScan == nil {
		// Freshness was deliberately not measured, so "never" would assert
		// something this scan never checked.
		if repo.Status.Freshness == model.FreshNotEvaluated {
			return "-"
		}
		if model.IsScanning(repo.Status.Configuration) {
			return "never"
		}
		return "-"
	}

	age := "unknown"
	if repo.StaleDays != nil {
		switch {
		case *repo.StaleDays == 0:
			age = "today"
		case *repo.StaleDays == 1:
			age = "1 day ago"
		default:
			age = fmt.Sprintf("%d days ago", *repo.StaleDays)
		}
	} else {
		age = repo.LastSuccessfulScan.UTC().Format("2006-01-02")
	}

	// Inactive repositories are on a monthly schedule, so the age alone would
	// be misleading without saying which threshold it is being judged against.
	if repo.Activity == model.ActivityInactive {
		return age + " (inactive)"
	}
	return age
}

// languageCell shows analyzed coverage as a fraction plus any problem
// languages, so a repository missing one language stands out.
func languageCell(repo model.Repo) string {
	if !model.IsScanning(repo.Status.Configuration) {
		if len(repo.DetectedLanguages) == 0 {
			return "-"
		}
		return fmt.Sprintf("0/%d detected", len(repo.DetectedLanguages))
	}

	configured := len(repo.ConfiguredLanguages)
	if configured == 0 && len(repo.DetectedLanguages) == 0 {
		return "-"
	}

	// Without runtime evidence there is no analyzed count, and rendering
	// "0/6" would read as six failures rather than six unmeasured languages.
	if repo.Status.Execution == model.ExecNotEvaluated {
		summary := fmt.Sprintf("%d configured", configured)
		if len(repo.MissingLanguages) > 0 {
			summary += " (not configured: " + model.JoinLanguages(repo.MissingLanguages) + ")"
		}
		return summary
	}

	succeeded := len(repo.SucceededLanguages)
	summary := fmt.Sprintf("%d/%d", succeeded, configured)

	var notes []string
	if len(repo.DeselectedLanguages) > 0 {
		notes = append(notes, "dropped after failing: "+model.JoinLanguages(repo.DeselectedLanguages))
	}
	if len(repo.FailedLanguages) > 0 {
		notes = append(notes, "not analyzed: "+model.JoinLanguages(repo.FailedLanguages))
	}
	if len(repo.MissingLanguages) > 0 {
		remaining := make([]model.Language, 0, len(repo.MissingLanguages))
		for _, language := range repo.MissingLanguages {
			if !containsLanguage(repo.DeselectedLanguages, language) {
				remaining = append(remaining, language)
			}
		}
		if len(remaining) > 0 {
			notes = append(notes, "not configured: "+model.JoinLanguages(remaining))
		}
	}
	if len(notes) == 0 {
		return summary
	}
	return summary + " (" + strings.Join(notes, "; ") + ")"
}

// containsLanguage reports whether a language appears in a list.
func containsLanguage(languages []model.Language, wanted model.Language) bool {
	for _, language := range languages {
		if language == wanted {
			return true
		}
	}
	return false
}

func detailCell(repo model.Repo) string {
	parts := append([]string(nil), repo.Status.Reasons...)
	for _, diagnostic := range repo.Diagnostics {
		message := diagnostic.Message
		if diagnostic.Source == model.SourceLog {
			message += " (from logs)"
		}
		parts = append(parts, message)
	}
	parts = append(parts, repo.Errors...)
	seen := make(map[string]bool, len(parts))
	unique := parts[:0]
	for _, part := range parts {
		if !seen[part] {
			unique = append(unique, part)
			seen[part] = true
		}
	}
	return strings.Join(unique, "; ")
}

func truncateLabel(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	// Truncating by byte would cut a multibyte character in half and emit
	// invalid UTF-8 into the terminal.
	return string(runes[:limit-3]) + "..."
}

func wrap(colour *color.Color) func(string) string {
	return func(value string) string { return colour.Sprint(value) }
}

// PropertyColumns returns a stable, de-duplicated list of property names to
// include as columns.
//
// Property lookup is case-insensitive, so names are folded before comparison.
// Organizations in the same enterprise routinely define the same property with
// different capitalization, and treating those as distinct would emit two
// columns that PropertyValue then fills with identical values.
func PropertyColumns(report *model.Report) []string {
	// Keyed by folded name, holding the spelling chosen for display.
	seen := map[string]string{}
	for _, repo := range report.Repositories {
		for name := range repo.Properties {
			folded := strings.ToLower(name)
			// Prefer the lexicographically smallest spelling so the column
			// heading does not depend on map iteration order.
			if existing, ok := seen[folded]; !ok || name < existing {
				seen[folded] = name
			}
		}
	}
	names := make([]string, 0, len(seen))
	for _, name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
