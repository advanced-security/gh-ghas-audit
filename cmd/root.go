package cmd

import (
	"fmt"
	"os"
	"github.com/spf13/cobra"

)

var Organizations string

var rootCmd = &cobra.Command{
	Use:   "gh-ghas-audit",
	Short: "Audit your GHAS deployment",
	Long: `Audit your GHAS deployment`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&Organizations, "organizations", "o", "", "Comma separated list of organizations to audit")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
	  fmt.Println(err)
	  os.Exit(1)
	}
}