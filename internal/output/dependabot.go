package output

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/cli/go-gh/v2/pkg/tableprinter"
	"github.com/fatih/color"

	"github.com/advanced-security/gh-ghas-audit/v2/internal/model"
)

// This file renders model.DependabotReport. It is a sibling to output.go and
// table.go (code scanning), not a modification of them: the two reports share
// no per-repository shape, so keeping their writers separate avoids coupling
// an unrelated format change in one to the other.

// WriteDependabotJSON emits the complete report document.
func WriteDependabotJSON(writer io.Writer, report *model.DependabotReport) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// WriteDependabotNDJSON emits a header record describing the run, followed by
// one record per repository so a consumer can stream results without
// buffering.
func WriteDependabotNDJSON(writer io.Writer, report *model.DependabotReport) error {
	encoder := json.NewEncoder(writer)

	header := map[string]any{
		"type":           "report",
		"schema_version": report.SchemaVersion,
		"generated_at":   report.GeneratedAt,
		"tool":           report.Tool,
		"scope":          report.Scope,
		"settings":       report.Settings,
		"summary":        report.Summary,
		"organizations":  report.Organizations,
		"warnings":       report.Warnings,
		"stats":          report.Stats,
	}
	if err := encoder.Encode(header); err != nil {
		return err
	}

	for index := range report.Repositories {
		record := struct {
			Type string `json:"type"`
			model.DependabotRepo
		}{Type: "repository", DependabotRepo: report.Repositories[index]}
		if err := encoder.Encode(record); err != nil {
			return err
		}
	}
	return nil
}

// dependabotCSVHeader is the per-repository CSV layout.
var dependabotCSVHeader = []string{
	"Organization",
	"Repository",
	"Overall status",
	"Evidence complete",
	"Dependency graph",
	"Dependency graph coverage",
	"Dependency graph manifests",
	"Manifests missing transitive deps",
	"Auto submission detected",
	"Auto submission action",
	"Dependabot alerts",
	"Open alerts",
	"Open critical alerts",
	"Open high alerts",
	"Open medium alerts",
	"Open low alerts",
	"Open malware alerts",
	"Oldest open alert",
	"Dependabot security updates",
	"Version updates",
	"Dependabot.yml path",
	"Ecosystems",
	"Uncovered ecosystems",
	"Target branches",
	"Registries configured",
	"Pull request health",
	"Open Dependabot PRs",
	"Open security update PRs",
	"Open version update PRs",
	"Open PRs with failing checks",
	"Oldest open PR",
	"Paused for inactivity",
	"Dependency review",
	"Dependency review branch",
	"Matched check context",
	"Visibility",
	"Archived",
	"Fork",
	"Default branch",
	"Reasons",
	"Errors",
	"Repository URL",
}

// WriteDependabotCSV emits one row per repository.
func WriteDependabotCSV(writer io.Writer, report *model.DependabotReport) error {
	csvWriter := csv.NewWriter(writer)
	defer csvWriter.Flush()

	if err := csvWriter.Write(dependabotCSVHeader); err != nil {
		return err
	}

	for _, repo := range report.Repositories {
		if err := csvWriter.Write(dependabotRepositoryRow(repo)); err != nil {
			return err
		}
	}

	csvWriter.Flush()
	return csvWriter.Error()
}

func dependabotRepositoryRow(repo model.DependabotRepo) []string {
	return []string{
		repo.Organization,
		repo.Name,
		string(repo.Status.Overall),
		strconv.FormatBool(!repo.Status.Incomplete),
		string(repo.Status.DependencyGraph),
		string(repo.Status.DependencyGraphCoverage),
		strconv.Itoa(repo.DependencyGraph.TotalManifests),
		strings.Join(repo.DependencyGraph.ManifestsMissingTransitive, "; "),
		strconv.FormatBool(repo.DependencyGraph.AutoSubmissionDetected),
		repo.DependencyGraph.AutoSubmissionAction,
		string(repo.Status.DependabotAlerts),
		strconv.Itoa(repo.Alerts.OpenTotal),
		strconv.Itoa(repo.Alerts.OpenCritical),
		strconv.Itoa(repo.Alerts.OpenHigh),
		strconv.Itoa(repo.Alerts.OpenMedium),
		strconv.Itoa(repo.Alerts.OpenLow),
		strconv.Itoa(repo.Alerts.OpenMalware),
		formatTime(repo.Alerts.OldestOpen),
		string(repo.Status.DependabotSecurityUpdates),
		string(repo.Status.VersionUpdates),
		repo.VersionUpdates.ConfigPath,
		strings.Join(repo.VersionUpdates.Ecosystems, ", "),
		strings.Join(repo.VersionUpdates.UncoveredEcosystems, ", "),
		strings.Join(repo.VersionUpdates.TargetBranches, ", "),
		strings.Join(repo.VersionUpdates.RegistriesConfigured, ", "),
		string(repo.Status.PullRequestHealth),
		strconv.Itoa(repo.PullRequests.Open),
		strconv.Itoa(repo.PullRequests.OpenSecurityUpdates),
		strconv.Itoa(repo.PullRequests.OpenVersionUpdates),
		strconv.Itoa(repo.PullRequests.OpenFailingChecks),
		formatTime(repo.PullRequests.OldestOpen),
		strconv.FormatBool(repo.PullRequests.PausedForInactivity),
		string(repo.Status.DependencyReview),
		repo.DependencyReview.Branch,
		repo.DependencyReview.MatchedCheckContext,
		repo.Visibility,
		strconv.FormatBool(repo.Archived),
		strconv.FormatBool(repo.Fork),
		repo.DefaultBranch,
		strings.Join(repo.Status.Reasons, "; "),
		strings.Join(repo.Errors, "; "),
		repo.URL,
	}
}

// WriteDependabotTable renders a summary followed by a repository table.
func WriteDependabotTable(writer io.Writer, report *model.DependabotReport, opts TableOptions) error {
	if err := writeDependabotSummary(writer, report, opts.IsTerminal); err != nil {
		return err
	}

	if len(report.Repositories) == 0 {
		if _, err := fmt.Fprintln(writer, "\nNo repositories matched the current scope and filters."); err != nil {
			return err
		}
		return writeDependabotFooter(writer, report, opts.IsTerminal)
	}

	buffered := bufio.NewWriter(writer)
	printer := tableprinter.New(buffered, opts.IsTerminal, opts.Width)
	headerColor := wrap(colorFor(opts.IsTerminal, color.FgHiWhite, color.Bold))

	headers := []string{
		"HEALTH", "REPOSITORY", "DEP GRAPH", "GRAPH COVERAGE", "ALERTS",
		"VERSION UPDATES", "PR HEALTH", "DEP REVIEW",
	}
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
		printer.AddField(dependencyGraphCell(repo), tableprinter.WithTruncate(nil))
		printer.AddField(string(repo.Status.DependencyGraphCoverage), tableprinter.WithTruncate(nil))
		printer.AddField(alertsCell(repo), tableprinter.WithTruncate(nil))
		printer.AddField(string(repo.Status.VersionUpdates), tableprinter.WithTruncate(nil))
		printer.AddField(pullRequestCell(repo), tableprinter.WithTruncate(nil))
		printer.AddField(string(repo.Status.DependencyReview), tableprinter.WithTruncate(nil))
		for _, property := range opts.Properties {
			value, _ := model.PropertyValue(repo.Properties, property)
			printer.AddField(value, tableprinter.WithTruncate(nil))
		}
		if opts.Detailed {
			printer.AddField(dependabotDetailCell(repo), tableprinter.WithTruncate(nil))
		}
		printer.EndRow()
	}

	if err := printer.Render(); err != nil {
		return err
	}
	if err := buffered.Flush(); err != nil {
		return err
	}

	return writeDependabotFooter(writer, report, opts.IsTerminal)
}

func dependencyGraphCell(repo model.DependabotRepo) string {
	if repo.Status.DependencyGraph == model.FeatureNotEvaluated {
		return "-"
	}
	return string(repo.Status.DependencyGraph)
}

func alertsCell(repo model.DependabotRepo) string {
	if !repo.Alerts.Evaluated {
		return "-"
	}
	if repo.Alerts.OpenTotal == 0 {
		return "0 open"
	}
	if repo.Alerts.OpenMalware > 0 {
		return fmt.Sprintf("%d open (%d crit, %d high, %d MALWARE)", repo.Alerts.OpenTotal, repo.Alerts.OpenCritical, repo.Alerts.OpenHigh, repo.Alerts.OpenMalware)
	}
	return fmt.Sprintf("%d open (%d crit, %d high)", repo.Alerts.OpenTotal, repo.Alerts.OpenCritical, repo.Alerts.OpenHigh)
}

func pullRequestCell(repo model.DependabotRepo) string {
	if !repo.PullRequests.Evaluated {
		return "-"
	}
	if repo.PullRequests.OpenSecurityUpdates > 0 {
		return fmt.Sprintf("%s (%d open: %d security, %d version)", string(repo.Status.PullRequestHealth),
			repo.PullRequests.Open, repo.PullRequests.OpenSecurityUpdates, repo.PullRequests.OpenVersionUpdates)
	}
	return fmt.Sprintf("%s (%d open)", string(repo.Status.PullRequestHealth), repo.PullRequests.Open)
}

func dependabotDetailCell(repo model.DependabotRepo) string {
	parts := append([]string(nil), repo.Status.Reasons...)
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

func writeDependabotSummary(writer io.Writer, report *model.DependabotReport, isTerminal bool) error {
	bold := colorFor(isTerminal, color.Bold)
	scope := report.Scope.Repository
	if scope == "" && report.Scope.Enterprise != "" {
		scope = fmt.Sprintf("enterprise %s (%d organizations)", report.Scope.Enterprise, len(report.Scope.Organizations))
	}
	if scope == "" {
		scope = strings.Join(report.Scope.Organizations, ", ")
	}

	if _, err := fmt.Fprintf(writer, "\n%s\n", bold.Sprintf("Dependabot / SCA health: %s", scope)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "%d repositories, %s needing attention (scan depth: %s)\n",
		report.Summary.TotalRepositories,
		colorFor(isTerminal, attentionColor(report.Summary.NeedsAttention)).Sprintf("%d", report.Summary.NeedsAttention),
		report.Settings.ScanDepth); err != nil {
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

	_, err := fmt.Fprintln(writer)
	return err
}

func writeDependabotFooter(writer io.Writer, report *model.DependabotReport, isTerminal bool) error {
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

// ResolveDependabotPropertyColumns returns the property columns to include in
// file output formats: every property found on any repository when none were
// explicitly requested, mirroring ResolvePropertyColumns for code scanning.
func ResolveDependabotPropertyColumns(report *model.DependabotReport, requested []string) []string {
	if len(requested) > 0 {
		return requested
	}
	seen := map[string]string{}
	for _, repo := range report.Repositories {
		for name := range repo.Properties {
			key := strings.ToLower(name)
			if _, ok := seen[key]; !ok {
				seen[key] = name
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	names := make([]string, 0, len(seen))
	for _, name := range seen {
		names = append(names, name)
	}
	return names
}
