// Package output renders a collected report. Every writer is a projection of
// the same model.Report, so the terminal, CSV and JSON views can never
// disagree about a repository's status.
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/advanced-security/gh-ghas-audit/internal/model"
)

// Format identifies an output representation.
type Format string

const (
	// FormatTable renders a human-readable terminal summary.
	FormatTable Format = "table"
	// FormatJSON renders the full canonical report document.
	FormatJSON Format = "json"
	// FormatNDJSON renders one repository per line, for very large estates
	// and streaming pipelines.
	FormatNDJSON Format = "ndjson"
	// FormatCSV renders one row per repository.
	FormatCSV Format = "csv"
	// FormatLanguageCSV renders one row per repository language, which is the
	// layout needed to answer per-language coverage questions.
	FormatLanguageCSV Format = "language-csv"
)

// ParseFormat resolves a user-supplied format name.
func ParseFormat(value string) (Format, error) {
	switch Format(strings.ToLower(strings.TrimSpace(value))) {
	case FormatTable:
		return FormatTable, nil
	case FormatJSON:
		return FormatJSON, nil
	case FormatNDJSON:
		return FormatNDJSON, nil
	case FormatCSV:
		return FormatCSV, nil
	case FormatLanguageCSV, "language_csv", "languages-csv":
		return FormatLanguageCSV, nil
	default:
		return "", fmt.Errorf("unsupported format %q; expected table, json, ndjson, csv or language-csv", value)
	}
}

// WriteJSON emits the complete report document.
func WriteJSON(writer io.Writer, report *model.Report) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// WriteNDJSON emits a header record describing the run, followed by one record
// per repository so a consumer can stream results without buffering.
func WriteNDJSON(writer io.Writer, report *model.Report) error {
	encoder := json.NewEncoder(writer)

	header := map[string]any{
		"type":           "report",
		"schema_version": report.SchemaVersion,
		"generated_at":   report.GeneratedAt,
		"tool":           report.Tool,
		"scope":          report.Scope,
		"settings":       report.Settings,
		"summary":        report.Summary,
		"warnings":       report.Warnings,
		"stats":          report.Stats,
	}
	if err := encoder.Encode(header); err != nil {
		return err
	}

	for index := range report.Repositories {
		record := struct {
			Type string `json:"type"`
			model.Repo
		}{Type: "repository", Repo: report.Repositories[index]}
		if err := encoder.Encode(record); err != nil {
			return err
		}
	}
	return nil
}

// repositoryCSVHeader is the per-repository CSV layout.
var repositoryCSVHeader = []string{
	"Organization",
	"Repository",
	"Overall status",
	"Evidence complete",
	"Configuration status",
	"Execution status",
	"Freshness status",
	"Coverage status",
	"Default setup state",
	"Security configuration",
	"Attachment status",
	"Detected languages",
	"Configured languages",
	"Analyzed languages",
	"Languages not analyzed",
	"Languages not configured",
	"Languages CodeQL cannot analyze",
	"Last successful scan",
	"Days since last scan",
	"Latest run conclusion",
	"Latest run started",
	"Latest run URL",
	"Schedule",
	"Query suite",
	"Visibility",
	"Archived",
	"Fork",
	"Default branch",
	"Diagnostics",
	"Reasons",
	"Errors",
	"Repository URL",
}

// WriteCSV emits one row per repository.
func WriteCSV(writer io.Writer, report *model.Report, propertyColumns []string) error {
	csvWriter := csv.NewWriter(writer)
	defer csvWriter.Flush()

	header := append([]string(nil), repositoryCSVHeader...)
	for _, property := range propertyColumns {
		header = append(header, "Property: "+property)
	}
	if err := csvWriter.Write(header); err != nil {
		return err
	}

	for _, repo := range report.Repositories {
		row := repositoryRow(repo)
		for _, property := range propertyColumns {
			row = append(row, repo.Properties[property])
		}
		if err := csvWriter.Write(row); err != nil {
			return err
		}
	}

	csvWriter.Flush()
	return csvWriter.Error()
}

func repositoryRow(repo model.Repo) []string {
	latest := repo.Execution.LatestCompletedRun
	if latest == nil {
		latest = repo.Execution.LatestRun
	}

	return []string{
		repo.Organization,
		repo.Name,
		string(repo.Status.Overall),
		strconv.FormatBool(!repo.Status.Incomplete),
		string(repo.Status.Configuration),
		string(repo.Status.Execution),
		string(repo.Status.Freshness),
		string(repo.Status.Coverage),
		repo.Configuration.DefaultSetupState,
		repo.Configuration.SecurityConfiguration,
		repo.Configuration.AttachmentStatus,
		model.JoinLanguages(repo.DetectedLanguages),
		model.JoinLanguages(repo.ConfiguredLanguages),
		model.JoinLanguages(repo.SucceededLanguages),
		model.JoinLanguages(repo.FailedLanguages),
		model.JoinLanguages(repo.MissingLanguages),
		strings.Join(repo.UnsupportedLanguages, ", "),
		formatTime(repo.LastSuccessfulScan),
		formatDays(repo.StaleDays),
		runConclusion(latest),
		formatTime(runStarted(latest)),
		runURL(latest),
		repo.Configuration.Schedule,
		repo.Configuration.QuerySuite,
		repo.Visibility,
		strconv.FormatBool(repo.Archived),
		strconv.FormatBool(repo.Fork),
		repo.DefaultBranch,
		joinDiagnostics(repo.Diagnostics),
		strings.Join(repo.Status.Reasons, "; "),
		strings.Join(repo.Errors, "; "),
		repo.URL,
	}
}

// languageCSVHeader is the per-language CSV layout, which answers "which
// language in which repository is not being scanned".
var languageCSVHeader = []string{
	"Organization",
	"Repository",
	"Language",
	"Detected",
	"Configured",
	"Analyzed",
	"Succeeded",
	"Job conclusion",
	"Database updated",
	"Repository overall status",
	"Job URL",
}

// WriteLanguageCSV emits one row per repository language.
func WriteLanguageCSV(writer io.Writer, report *model.Report, propertyColumns []string) error {
	csvWriter := csv.NewWriter(writer)
	defer csvWriter.Flush()

	header := append([]string(nil), languageCSVHeader...)
	for _, property := range propertyColumns {
		header = append(header, "Property: "+property)
	}
	if err := csvWriter.Write(header); err != nil {
		return err
	}

	for _, repo := range report.Repositories {
		states := repo.Languages
		if len(states) == 0 {
			// Emit a placeholder so repositories with nothing to analyze are
			// still represented and row counts reconcile with the repository
			// level export.
			states = []model.LanguageState{{}}
		}
		for _, state := range states {
			row := []string{
				repo.Organization,
				repo.Name,
				string(state.Language),
				strconv.FormatBool(state.Detected),
				strconv.FormatBool(state.Configured),
				strconv.FormatBool(state.Analyzed),
				strconv.FormatBool(state.Succeeded),
				state.JobConclusion,
				formatTime(state.DatabaseUpdatedAt),
				string(repo.Status.Overall),
				state.JobURL,
			}
			for _, property := range propertyColumns {
				row = append(row, repo.Properties[property])
			}
			if err := csvWriter.Write(row); err != nil {
				return err
			}
		}
	}

	csvWriter.Flush()
	return csvWriter.Error()
}

func joinDiagnostics(diagnostics []model.Diagnostic) string {
	if len(diagnostics) == 0 {
		return ""
	}
	parts := make([]string, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		label := diagnostic.Code
		if label == "" {
			label = diagnostic.Message
		}
		if diagnostic.Language != "" {
			label = fmt.Sprintf("%s[%s]", label, diagnostic.Language)
		}
		if diagnostic.Source == model.SourceLog {
			label += " (log)"
		}
		parts = append(parts, label)
	}
	return strings.Join(parts, "; ")
}

func formatTime(value *model.Timestamp) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format("2006-01-02T15:04:05Z")
}

func formatDays(value *int) string {
	if value == nil {
		return ""
	}
	return strconv.Itoa(*value)
}

func runConclusion(run *model.RunRef) string {
	if run == nil {
		return ""
	}
	if run.Conclusion != "" {
		return run.Conclusion
	}
	return run.Status
}

func runStarted(run *model.RunRef) *model.Timestamp {
	if run == nil {
		return nil
	}
	return run.StartedAt
}

func runURL(run *model.RunRef) string {
	if run == nil {
		return ""
	}
	return run.URL
}
