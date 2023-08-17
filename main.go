package main

import (
	"os"
	"fmt"
	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/cli/go-gh/v2/pkg/tableprinter"
)

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

func main() {
	client, err := api.DefaultRESTClient()
	if err != nil {
		fmt.Println(err)
		return
	}
	printer := tableprinter.New(os.Stdout, true, 80)
	printer.AddField("Organization")
	printer.AddField("Repository")
	printer.AddField("Default Setup")
	printer.EndRow()
	orgs := []string {"advanced-security-demo"}
	// var orgs []string
	// if orgs, err = listOrgs(client); err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	for _, org := range orgs {
		var repos []string
		if repos, err = listRepos(client, org); err != nil {
			fmt.Println(err)
			return
		}
		for _, repo := range repos {
			printer.AddField(org)
			printer.AddField(repo)

			if defaultSetup, err := getDefaultSetup(client, org, repo); err == nil {
				if defaultSetup.State == "configured" {
					printer.AddField(fmt.Sprintf("Configured for: %s", defaultSetup.Languages))
				} else {
					printer.AddField("Disabled")
				}
			} else {
				printer.AddField("Unknown")
			}

			printer.EndRow()
		}
	}

	printer.Render()
}