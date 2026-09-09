package cmd

import (
	"errors"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Holds flags for organizations and repository.
var (
	Organizations         string
	Repository            string
	SecurityConfiguration string // Security configuration name to filter repos
	CSVOutput             string // File path for CSV output
	SkipArchived          bool   // Skip archived repositories
	SkipForks             bool   // Skip forked repositories
)

// rootCmd is the base command called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "gh-ghas-audit",
	Short: "Audit your GHAS deployment",
	Long:  `Audit your GHAS deployment`,
	// Errors are printed by Execute so that a requested exit code can be
	// returned without an empty "Error:" line.
	SilenceErrors: true,
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}

// buildVersion is overridden at release time via -ldflags.
var buildVersion = ""

// version reports the extension version, preferring a linker-provided value
// and falling back to module build information.
func version() string {
	if buildVersion != "" {
		return buildVersion
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "dev"
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the extension version",
	Run: func(cmd *cobra.Command, _ []string) {
		fmt.Fprintln(cmd.OutOrStdout(), version())
	},
}

// normalizeFlagNames accepts --organization as an alias for --organizations,
// which is the singular form most users type first.
func normalizeFlagNames(_ *pflag.FlagSet, name string) pflag.NormalizedName {
	if name == "organization" {
		name = "organizations"
	}
	return pflag.NormalizedName(name)
}

func init() {
	// Applies to this command and every subcommand, so --organization works
	// wherever --organizations is accepted.
	rootCmd.SetGlobalNormalizationFunc(normalizeFlagNames)

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
	rootCmd.PersistentFlags().StringVar(
		&SecurityConfiguration,
		"security-configuration",
		"",
		"Filter repositories by security configuration name",
	)
	rootCmd.PersistentFlags().BoolVar(
		&SkipArchived,
		"skip-archived",
		false,
		"Skip archived repositories",
	)
	rootCmd.PersistentFlags().BoolVar(
		&SkipForks,
		"skip-forks",
		false,
		"Skip forked repositories",
	)

	// Attach code-scanning subcommand.
	rootCmd.AddCommand(codeScanningAuditCmd)
	rootCmd.AddCommand(versionCmd)
}

// Execute runs the main CLI command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		// A requested exit code carries no message of its own.
		var coded *exitCodeError
		if errors.As(err, &coded) {
			os.Exit(coded.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
