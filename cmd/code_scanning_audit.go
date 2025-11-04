package cmd

import (
	"fmt"
	"strings"

	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/cli/go-gh/v2/pkg/term"
	"github.com/spf13/cobra"
)

var codeScanningAuditCmd = &cobra.Command{
	Use:   "code-scanning",
	Short: "Audit your code scanning setup",
	Long:  `Audit your code scanning setup`,
	Run:   runCodeScanningAudit,
}

// processRepository processes a single repository and returns a report entry
func processRepository(client *api.RESTClient, org, repo string) ReportEntry {
	languageCoverage, err := GetLanguages(client, org, repo)
	if err != nil {
		fmt.Println("Error getting languages:", err)
		languageCoverage = make(LanguageCoverage)
	}
	repoLangs := NormalizeLanguages(languageCoverage)

	defaultSetup, err := GetDefaultSetup(client, org, repo)
	if err != nil {
		unknownReason := "Unknown"
		if strings.Contains(err.Error(), "Advanced Security must be enabled") {
			unknownReason = "GHAS is not enabled"
		}
		return ReportEntry{
			Organization:           org,
			Repository:             repo,
			DefaultSetupEnabled:    unknownReason,
			LanguagesInRepo:        strings.Join(repoLangs, ", "),
			DefaultSetupConfigured: "Unknown",
			NotConfiguredLangs:     "Unknown",
		}
	}

	defaultSetupEnabled := "Disabled"
	if strings.ToLower(defaultSetup.State) == "configured" {
		defaultSetupEnabled = "Enabled"
	}

	confLangs := []string{}
	seen := make(map[string]bool)
	for _, c := range defaultSetup.Languages {
		mapped, ok := LANGUAGE_MAPPING[strings.ToLower(c)]
		if !ok {
			continue
		}
		if !seen[mapped] {
			seen[mapped] = true
			confLangs = append(confLangs, mapped)
		}
	}

	configurable := ArrayDiff(repoLangs, confLangs)
	return ReportEntry{
		Organization:           org,
		Repository:             repo,
		DefaultSetupEnabled:    defaultSetupEnabled,
		LanguagesInRepo:        strings.Join(repoLangs, ", "),
		DefaultSetupConfigured: strings.Join(confLangs, ", "),
		NotConfiguredLangs:     strings.Join(configurable, ", "),
	}
}

func runCodeScanningAudit(c *cobra.Command, args []string) {
	fmt.Println("Starting audit...")

	client, err := api.DefaultRESTClient()
	if err != nil {
		fmt.Println("Error initializing API client:", err)
		return
	}

	// Initialize the report
	report := &Report{}

	// Determine the output printer
	var printer Printer
	if CSVOutput != "" {
		fmt.Println("CSV output enabled. Writing to", CSVOutput)
		csvPrinter, err := NewCSVPrinter(CSVOutput)
		if err != nil {
			fmt.Println("Error initializing CSV printer:", err)
			return
		}
		printer = csvPrinter
	} else {
		terminal := term.FromEnv()
		termWidth, _, _ := terminal.Size()
		printer = NewTerminalPrinter(terminal.Out(), terminal.IsTerminalOutput(), termWidth)
	}

	// If single repository is provided.
	if Repository != "" {
		fmt.Println("Processing single repository:", Repository)
		org, singleRepo := ParseRepository(Repository)
		if org == "" || singleRepo == "" {
			fmt.Printf("Invalid repository format: %s\n", Repository)
			return
		}

		entry := processRepository(client, org, singleRepo)
		report.Entries = append(report.Entries, entry)
	} else {
		// Otherwise, handle multiple organizations
		orgs := strings.Split(Organizations, ",")
		if len(orgs) == 0 || (len(orgs) == 1 && orgs[0] == "") {
			fmt.Println("No organizations or repository provided.")
			_ = c.Help()
			return
		}

		for _, org := range orgs {
			org = strings.TrimSpace(org)
			fmt.Println("Processing organization:", org)
			repos, err := ListRepos(client, org)
			if err != nil {
				fmt.Println("Error listing repos for", org+":", err)
				return
			}
			fmt.Printf("Found %d repositories in %s\n", len(repos), org)
			for i, repo := range repos {
				fmt.Printf(" - Processing repository: %s [%d/%d]\n", repo, i+1, len(repos))
				entry := processRepository(client, org, repo)
				report.Entries = append(report.Entries, entry)
			}
			fmt.Println("Finished processing organization:", org)
		}
	}

	if err := printer.PrintReport(report); err != nil {
		fmt.Println("Error printing report:", err)
		return
	}

	fmt.Println("Audit complete!")
}
