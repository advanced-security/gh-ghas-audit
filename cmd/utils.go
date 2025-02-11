package cmd

import (
	"fmt"
	"strings"

	"github.com/cli/go-gh/v2/pkg/api"
)

// LANGUAGE_MAPPING normalizes different language names into a standard set.
var LANGUAGE_MAPPING = map[string]string{
	"actions":               "actions",
	"csharp":                "csharp",
	"c#":                    "csharp",
	"c-cpp":                 "c-cpp",
	"cpp":                   "c-cpp",
	"c":                     "c-cpp",
	"c++":                   "c-cpp",
	"go":                    "go",
	"java-kotlin":           "java-kotlin",
	"java":                  "java-kotlin",
	"javascript-typescript": "javascript-typescript",
	"javascript":            "javascript-typescript",
	"typescript":            "typescript",
	"python":                "python",
	"ruby":                  "ruby",
	"kotlin":                "java-kotlin",
	"swift":                 "swift",
}

// LanguageCoverage is the struct for the GitHub /languages API response.
type LanguageCoverage map[string]int

// DefaultSetupConfig is the response structure from code-scanning/default-setup.
type DefaultSetupConfig struct {
	State      string
	Languages  []string
	QuerySuite string
	UpdatedAt  string
	Scheduled  string
}

// normalizeLanguages returns a list of normalized languages matching LANGUAGE_MAPPING.
func NormalizeLanguages(langMap LanguageCoverage) []string {
	seen := make(map[string]bool)
	var result []string
	for k := range langMap {
		mapped, ok := LANGUAGE_MAPPING[strings.ToLower(k)]
		if !ok {
			continue
		}
		if !seen[mapped] {
			seen[mapped] = true
			result = append(result, mapped)
		}
	}
	return result
}

// parseRepository extracts the "org" and "repo" parts from "owner/repo".
func ParseRepository(repoString string) (string, string) {
	parts := strings.SplitN(repoString, "/", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

// listOrgs returns a list of organization names for the authenticated user.
func ListOrgs(client *api.RESTClient) ([]string, error) {
	response := []struct{ Login string }{}
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

// listRepos returns a list of repository names under a given org.
func ListRepos(client *api.RESTClient, org string) ([]string, error) {
	perPage := 100
	page := 1
	var repos []string

	for {
		url := fmt.Sprintf("orgs/%s/repos?per_page=%d&page=%d", org, perPage, page)
		var response []struct {
			Name string
		}
		err := client.Get(url, &response)
		if err != nil {
			return nil, err
		}
		numResults := len(response)
		if numResults == 0 {
			break
		}
		for _, repo := range response {
			repos = append(repos, repo.Name)
		}
		// if less than perPage, no more pages
		if numResults < perPage {
			break
		}
		page++
	}

	return repos, nil
}

// getDefaultSetup fetches the default setup configuration for a repository.
func GetDefaultSetup(client *api.RESTClient, org string, repo string) (DefaultSetupConfig, error) {
	response := DefaultSetupConfig{}
	err := client.Get(fmt.Sprintf("repos/%s/%s/code-scanning/default-setup", org, repo), &response)
	if err != nil {
		return response, err
	}
	return response, nil
}

// Languages returns a list of keys in the LanguageCoverage map.
func (l LanguageCoverage) Languages() []string {
	var keys []string
	for k := range l {
		keys = append(keys, k)
	}
	return keys
}

// getLanguages fetches a repository's language breakdown.
func GetLanguages(client *api.RESTClient, org string, repo string) (LanguageCoverage, error) {
	response := make(LanguageCoverage)
	err := client.Get(fmt.Sprintf("repos/%s/%s/languages", org, repo), &response)
	if err != nil {
		return response, err
	}
	return response, nil
}

// ArrayDiff returns elements in 'a' that are not in 'b'.
func ArrayDiff[K comparable](a []K, b []K) []K {
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
