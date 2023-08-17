package cmd

import (
	"os"
	"fmt"
	"strings"
	"github.com/spf13/cobra"
	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/cli/go-gh/v2/pkg/tableprinter"
)

func init() {
	rootCmd.AddCommand(audit_codeScanningCmd)
}

var audit_codeScanningCmd = &cobra.Command{
	Use:   "code-scanning",
	Short: "Audit your code scanning setup",
	Long: `Audit your code scanning setup`,
	Run: func(cmd *cobra.Command, args []string) {
		client, err := api.DefaultRESTClient()
		if err != nil {
			fmt.Println(err)
			return
		}
		printer := tableprinter.New(os.Stdout, true, 120)
		printer.AddField("Organization")
		printer.AddField("Repository")
		printer.AddField("Default Setup")
		printer.EndRow()
		orgs := strings.Split(Organizations, ",")
		if len(orgs) == 0 {
			orgs, err = listOrgs(client)
			if err != nil {
				fmt.Println(err)
				return
			}
		}
		for _, org := range orgs {
			var repos []string
			if repos, err = listRepos(client, org); err != nil {
				fmt.Println(err)
				return
			}
			for _, repo := range repos {
				printer.AddField(org)
				printer.AddField(repo)
	
				languageCoverage, err := getLanguages(client, org, repo)
				if err != nil {
					fmt.Println(err)
					languageCoverage = make(LanguageCoverage)
				}
	
				if defaultSetup, err := getDefaultSetup(client, org, repo); err == nil {
					if defaultSetup.State == "configured" {
						printer.AddField(fmt.Sprintf("Configured for: %s, not configured for: %s",
							defaultSetup.Languages,
							ArrayDiff(languageCoverage.Languages(), defaultSetup.Languages)))
					} else {
						printer.AddField(fmt.Sprintf("Disabled, missing coverage for %s", languageCoverage.Languages()))
					}
				} else {
					printer.AddField("Unknown")
				}
	
				printer.EndRow()
			}
		}
	
		printer.Render()
	},
}

func listOrgs(client *api.RESTClient)  ([]string, error) {
	response := []struct {Login string}{}
	err := client.Get("user/orgs", &response)
	if err != nil {
		return nil, err
	}
	orgs := make([]string, len(response))
	for i, org := range response {
		orgs[i] = org.Login
	}

	return orgs, nil
}

func listRepos(client *api.RESTClient, org string) ([]string, error) {
	response := []struct {Name string}{}
	err := client.Get(fmt.Sprintf("orgs/%s/repos", org ), &response)
	if err != nil {
		return nil, err
	}
	repos := make([]string, len(response))
	for i, repo := range response {
		repos[i] = repo.Name
	}

	return repos, nil
}

type DefaultSetupConfig struct {
	State string
	Languages []string
	QuerySuite string
	UpdatedAt string
	Scheduled string
}

func getDefaultSetup(client *api.RESTClient, org string, repo string) (DefaultSetupConfig, error) {
	response := DefaultSetupConfig{}
	err := client.Get(fmt.Sprintf("repos/%s/%s/code-scanning/default-setup", org, repo), &response)
	if err != nil {
		return response, err
	}

	return response, nil
	
}

type LanguageCoverage map[string]int

func (l LanguageCoverage) Languages() []string {
	var keys []string
	for k := range l {
		keys = append(keys, k)
	}
	return keys
}

func getLanguages(client *api.RESTClient, org string, repo string) (LanguageCoverage, error) {
	response := make(LanguageCoverage)
	err := client.Get(fmt.Sprintf("repos/%s/%s/languages", org, repo), &response)
	if err != nil {
		return response, err
	}

	return response, nil
}

func ArrayDiff[K comparable] (a []K, b []K) []K {
	m := make(map[K]bool)
	for _, item := range b {
		m[item] = true
	}
	var diff []K
	for _, item := range a {
		if _, ok := m[item]; !ok {
			diff = append(diff, item)
		}
	}
	return diff
}