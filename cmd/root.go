package cmd

import (
	"errors"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type scopeOptions struct {
	organizations         string
	repository            string
	securityConfiguration string
	skipArchived          bool
	skipForks             bool
}

// buildVersion is overridden at release time via -ldflags.
var buildVersion = ""

// version reports the extension version, preferring a linker-provided value
// and falling back to module build information.
func version() string {
	if buildVersion != "" {
		return buildVersion
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "2.0.0-dev"
}

// normalizeFlagNames accepts --organization as an alias for --organizations,
// which is the singular form most users type first.
func normalizeFlagNames(_ *pflag.FlagSet, name string) pflag.NormalizedName {
	if name == "organization" {
		name = "organizations"
	}
	return pflag.NormalizedName(name)
}

func newRootCommand() *cobra.Command {
	scope := &scopeOptions{}
	rootCmd := &cobra.Command{
		Use:           "gh-ghas-audit",
		Short:         "Audit your GHAS deployment",
		Version:       version(),
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	rootCmd.SetGlobalNormalizationFunc(normalizeFlagNames)

	rootCmd.PersistentFlags().StringVarP(
		&scope.organizations,
		"organizations",
		"o",
		"",
		"Comma separated list of organizations to audit",
	)
	rootCmd.PersistentFlags().StringVarP(
		&scope.repository,
		"repository",
		"r",
		"",
		"Single repository to audit",
	)
	rootCmd.PersistentFlags().StringVar(
		&scope.securityConfiguration,
		"security-configuration",
		"",
		"Filter repositories by security configuration name",
	)
	rootCmd.PersistentFlags().BoolVar(
		&scope.skipArchived,
		"skip-archived",
		false,
		"Skip archived repositories",
	)
	rootCmd.PersistentFlags().BoolVar(
		&scope.skipForks,
		"skip-forks",
		false,
		"Skip forked repositories",
	)

	rootCmd.AddCommand(newCodeScanningCommand(scope))
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the extension version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version())
		},
	})
	return rootCmd
}

// Execute runs the main CLI command.
func Execute() {
	if err := newRootCommand().Execute(); err != nil {
		// A requested exit code carries no message of its own.
		var coded *exitCodeError
		if errors.As(err, &coded) {
			os.Exit(coded.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
