package output

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/cli/go-gh/v2/pkg/tableprinter"
	"github.com/fatih/color"

	"github.com/advanced-security/gh-ghas-audit/internal/model"
)

// severityColor maps a severity onto a terminal colour so that problems are
// visually obvious in a long list.
func severityColor(severity model.Severity) *color.Color {
	switch severity {
	case model.SeverityFailing:
		return color.New(color.FgRed, color.Bold)
	case model.SeverityStalled:
		return color.New(color.FgRed)
	case model.SeverityStale:
		return color.New(color.FgYellow, color.Bold)
	case model.SeverityDegraded:
		return color.New(color.FgYellow)
	case model.SeverityInProgress:
		return color.New(color.FgBlue)
	case model.SeverityHealthy:
		return color.New(color.FgGreen)
	default:
		return color.New(color.FgHiBlack)
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

// WriteTable renders a summary followed by a repository table.
func WriteTable(writer io.Writer, report *model.Report, opts TableOptions) error {
	writeSummary(writer, report)

	if len(report.Repositories) == 0 {
		fmt.Fprintln(writer, "\nNo repositories matched the current scope and filters.")
		return nil
	}

	printer := tableprinter.New(writer, opts.IsTerminal, opts.Width)
	headerColor := wrap(color.New(color.FgHiWhite, color.Bold))

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
		statusColor := wrap(severityColor(repo.Status.Overall))
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

	writeFooter(writer, report)
	return nil
}

func writeSummary(writer io.Writer, report *model.Report) {
	bold := color.New(color.Bold)
	scope := report.Scope.Repository
	if scope == "" && report.Scope.Enterprise != "" {
		scope = fmt.Sprintf("enterprise %s (%d organizations)", report.Scope.Enterprise, len(report.Scope.Organizations))
	}
	if scope == "" {
		scope = strings.Join(report.Scope.Organizations, ", ")
	}

	fmt.Fprintf(writer, "\n%s\n", bold.Sprintf("Code scanning status: %s", scope))
	fmt.Fprintf(writer, "%d repositories, %s needing attention. Scans are stale after %s for active repositories",
		report.Summary.TotalRepositories,
		color.New(attentionColor(report.Summary.NeedsAttention)).Sprintf("%d", report.Summary.NeedsAttention),
		report.Settings.StaleAfter)
	switch report.Settings.StaleAfterInactive {
	case "", "off":
		fmt.Fprintln(writer, "; inactive repositories are not checked")
	default:
		fmt.Fprintf(writer, " and %s for inactive ones\n", report.Settings.StaleAfterInactive)
	}

	fmt.Fprintln(writer)
	for _, severity := range model.AllSeverities() {
		count := report.Summary.BySeverity[string(severity)]
		if count == 0 {
			continue
		}
		fmt.Fprintf(writer, "  %-16s %s\n",
			string(severity),
			severityColor(severity).Sprintf("%d", count))
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
		fmt.Fprintf(writer, "\n%s\n", bold.Sprintf("By %s", label))
		groups := report.Summary.Groups
		if len(groups) > 15 {
			groups = groups[:15]
		}
		for _, group := range groups {
			fmt.Fprintf(writer, "  %-30s %3d repositories, %s needing attention\n",
				truncateLabel(group.Value, 30),
				group.Repositories,
				color.New(attentionColor(group.NeedsAttention)).Sprintf("%d", group.NeedsAttention))
		}
		if len(report.Summary.Groups) > len(groups) {
			fmt.Fprintf(writer, "  ... and %d more groups\n", len(report.Summary.Groups)-len(groups))
		}
	}

	fmt.Fprintln(writer)
}

func writeFooter(writer io.Writer, report *model.Report) {
	if len(report.Warnings) > 0 {
		fmt.Fprintf(writer, "\n%s\n", color.New(color.FgYellow, color.Bold).Sprint("Warnings"))
		for _, warning := range report.Warnings {
			fmt.Fprintf(writer, "  - %s\n", warning)
		}
	}

	if report.Stats.Incomplete {
		fmt.Fprintf(writer, "\n%s\n", color.New(color.FgYellow).Sprint(
			"This report is incomplete. Absence of a problem here does not prove absence of a problem."))
	}

	fmt.Fprintf(writer, "\n%d API requests, %d cached, %d GraphQL queries in %.1fs",
		report.Stats.APIRequests, report.Stats.CacheHits, report.Stats.GraphQLRequests, report.Stats.DurationSeconds)
	if report.Stats.RateLimitRemains > 0 {
		fmt.Fprintf(writer, ", %d rate limit remaining", report.Stats.RateLimitRemains)
	}
	fmt.Fprintln(writer)
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
		if repo.Status.Configuration == model.ConfigConfigured {
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
	if repo.Status.Configuration != model.ConfigConfigured && repo.Status.Configuration != model.ConfigAttachFailed {
		if len(repo.DetectedLanguages) == 0 {
			return "-"
		}
		return fmt.Sprintf("0/%d detected", len(repo.DetectedLanguages))
	}

	configured := len(repo.ConfiguredLanguages)
	if configured == 0 && len(repo.DetectedLanguages) == 0 {
		return "-"
	}

	succeeded := len(repo.SucceededLanguages)
	summary := fmt.Sprintf("%d/%d", succeeded, configured)

	var notes []string
	if len(repo.FailedLanguages) > 0 {
		notes = append(notes, "not analyzed: "+model.JoinLanguages(repo.FailedLanguages))
	}
	if len(repo.MissingLanguages) > 0 {
		notes = append(notes, "not configured: "+model.JoinLanguages(repo.MissingLanguages))
	}
	if len(notes) == 0 {
		return summary
	}
	return summary + " (" + strings.Join(notes, "; ") + ")"
}

func detailCell(repo model.Repo) string {
	parts := append([]string(nil), repo.Status.Reasons...)
	for _, diagnostic := range repo.Diagnostics {
		if diagnostic.Source == model.SourceLog {
			parts = append(parts, diagnostic.Message+" (from logs)")
		}
	}
	parts = append(parts, repo.Errors...)
	return strings.Join(parts, "; ")
}

func truncateLabel(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit-3] + "..."
}

func wrap(colour *color.Color) func(string) string {
	return func(value string) string { return colour.Sprint(value) }
}

// PropertyColumns returns a stable, de-duplicated list of property names to
// include as columns.
func PropertyColumns(report *model.Report) []string {
	seen := map[string]bool{}
	for _, repo := range report.Repositories {
		for name := range repo.Properties {
			seen[name] = true
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
