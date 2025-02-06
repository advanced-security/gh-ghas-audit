package cmd

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"

	"github.com/cli/go-gh/v2/pkg/tableprinter"
	"github.com/fatih/color"
)

// ReportEntry represents a single row in the audit report.
type ReportEntry struct {
	Organization           string
	Repository             string
	DefaultSetupEnabled    string
	LanguagesInRepo        string
	DefaultSetupConfigured string
	NotConfiguredLangs     string
}

// Report holds all the audit results.
type Report struct {
	Entries []ReportEntry
}

// Printer interface for outputting the report.
type Printer interface {
	PrintReport(report *Report) error
}

// TerminalPrinter prints the report to the terminal.
type TerminalPrinter struct {
	TablePrinter tableprinter.TablePrinter
}

// CSVPrinter prints the report to a CSV file.
type CSVPrinter struct {
	Writer *csv.Writer
	File   *os.File
}

func NewCSVPrinter(filePath string) (*CSVPrinter, error) {
	file, err := os.Create(filePath)
	if err != nil {
		return nil, err
	}

	writer := csv.NewWriter(file)

	// Write CSV header
	header := []string{
		"Organization",
		"Repository",
		"Default setup enabled?",
		"Languages in repo",
		"Default setup configured",
		"Not configured (supported languages)",
	}
	if err := writer.Write(header); err != nil {
		return nil, fmt.Errorf("error writing CSV header: %w", err)
	}

	return &CSVPrinter{
		Writer: writer,
		File:   file,
	}, nil
}

// PrintReport prints the report to the terminal.
func (tp *TerminalPrinter) PrintReport(report *Report) error {
	// Loop through entries using a local variable to speed up repeated look-ups.
	for _, entry := range report.Entries {
		tp.TablePrinter.AddField(entry.Organization, tableprinter.WithColor(wrapColorFunc(color.New(color.FgGreen).SprintfFunc())))
		tp.TablePrinter.AddField(entry.Repository, tableprinter.WithColor(wrapColorFunc(color.New(color.FgGreen).SprintfFunc())))
		tp.TablePrinter.AddField(entry.DefaultSetupEnabled, tableprinter.WithColor(wrapColorFunc(color.New(color.FgGreen).SprintfFunc())))
		tp.TablePrinter.AddField(entry.LanguagesInRepo, tableprinter.WithColor(wrapColorFunc(color.New(color.FgYellow).SprintfFunc())))
		tp.TablePrinter.AddField(entry.DefaultSetupConfigured, tableprinter.WithColor(wrapColorFunc(color.New(color.FgYellow).SprintfFunc())))
		tp.TablePrinter.AddField(entry.NotConfiguredLangs, tableprinter.WithColor(wrapColorFunc(color.New(color.FgYellow).SprintfFunc())))
		tp.TablePrinter.EndRow()
	}
	return tp.TablePrinter.Render()
}

// PrintReport prints the report to a CSV file.
func (cp *CSVPrinter) PrintReport(report *Report) error {
	for _, entry := range report.Entries {
		row := []string{
			entry.Organization,
			entry.Repository,
			entry.DefaultSetupEnabled,
			entry.LanguagesInRepo,
			entry.DefaultSetupConfigured,
			entry.NotConfiguredLangs,
		}
		if err := cp.Writer.Write(row); err != nil {
			return fmt.Errorf("error writing CSV row: %w", err)
		}
	}
	cp.Writer.Flush()
	return cp.File.Close()
}

// wrapColorFunc wraps a color function to match the expected type.
func wrapColorFunc(f func(format string, a ...interface{}) string) func(string) string {
	return func(s string) string {
		return f("%s", s)
	}
}

// NewTerminalPrinter creates a new TerminalPrinter.
func NewTerminalPrinter(out io.Writer, isTerminal bool, termWidth int) *TerminalPrinter {
	tp := tableprinter.New(out, isTerminal, termWidth)
	tp.AddField("Organization", tableprinter.WithColor(wrapColorFunc(color.New(color.FgHiWhite).SprintfFunc())), tableprinter.WithTruncate(nil))
	tp.AddField("Repository", tableprinter.WithColor(wrapColorFunc(color.New(color.FgHiWhite).SprintfFunc())), tableprinter.WithTruncate(nil))
	tp.AddField("Default setup enabled?", tableprinter.WithColor(wrapColorFunc(color.New(color.FgHiWhite).SprintfFunc())), tableprinter.WithTruncate(nil))
	tp.AddField("Languages in repo", tableprinter.WithColor(wrapColorFunc(color.New(color.FgHiWhite).SprintfFunc())), tableprinter.WithTruncate(nil))
	tp.AddField("Default setup configured", tableprinter.WithColor(wrapColorFunc(color.New(color.FgHiWhite).SprintfFunc())), tableprinter.WithTruncate(nil))
	tp.AddField("Not configured (supported languages)", tableprinter.WithColor(wrapColorFunc(color.New(color.FgHiWhite).SprintfFunc())), tableprinter.WithTruncate(nil))
	tp.EndRow()

	return &TerminalPrinter{TablePrinter: tp}
}
