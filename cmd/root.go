package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Holds flags for organizations and repository.
var (
	Organizations string
	Repository    string
	CSVOutput     string // File path for CSV output
)

// rootCmd is the base command called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "gh-ghas-audit",
	Short: "Audit your GHAS deployment",
	Long:  `Audit your GHAS deployment`,
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(
		&Organizations,
		"organizations",
		"o",
		"",
		"Comma separated list of organizations to audit",
	)
	rootCmd.PersistentFlags().StringVarP(
		&Repository,
		"repository",
		"r",
		"",
		"Single repository to audit",
	)
	rootCmd.PersistentFlags().StringVar(
		&CSVOutput,
		"csv-output",
		"",
		"File path to output CSV report",
	)

	// Attach code-scanning subcommand.
	rootCmd.AddCommand(codeScanningAuditCmd)
}

// Execute runs the main CLI command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
