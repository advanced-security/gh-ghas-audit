package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/advanced-security/gh-ghas-audit/internal/ghapi"
)

// enterpriseOrganizations lists every organization in an enterprise.
//
// There is no REST endpoint for this, so GraphQL is used. The query requires
// an enterprise-scoped token; a clearer error is returned when it is missing
// because this is the most common first-run failure.
func (c *Collector) enterpriseOrganizations(ctx context.Context, slug string) ([]string, error) {
	const query = `query($slug:String!,$cursor:String){
  enterprise(slug:$slug){
    organizations(first:100,after:$cursor){
      pageInfo{hasNextPage endCursor}
      nodes{login}
    }
  }
}`

	var logins []string
	cursor := ""
	for {
		var response struct {
			Enterprise *struct {
				Organizations struct {
					PageInfo struct {
						HasNextPage bool   `json:"hasNextPage"`
						EndCursor   string `json:"endCursor"`
					} `json:"pageInfo"`
					Nodes []struct {
						Login string `json:"login"`
					} `json:"nodes"`
				} `json:"organizations"`
			} `json:"enterprise"`
		}

		variables := map[string]any{"slug": slug, "cursor": (*string)(nil)}
		if cursor != "" {
			variables["cursor"] = cursor
		}

		if err := c.client.GraphQL(ctx, query, variables, &response); err != nil {
			message := err.Error()
			if strings.Contains(message, "read:enterprise") || strings.Contains(message, "INSUFFICIENT_SCOPES") {
				return nil, fmt.Errorf(
					"listing organizations for enterprise %q requires an enterprise-scoped token: "+
						"run `gh auth refresh -h %s -s read:enterprise`, or pass --organization explicitly: %w",
					slug, c.client.Host(), err)
			}
			if strings.Contains(message, "Could not resolve to a Business") || strings.Contains(message, "NOT_FOUND") {
				return nil, fmt.Errorf(
					"enterprise %q was not found or is not visible to this token; "+
						"check the slug used in your enterprise URL, or pass --organization explicitly",
					slug)
			}
			return nil, fmt.Errorf("listing organizations for enterprise %q: %w", slug, err)
		}

		if response.Enterprise == nil {
			// A token without read:enterprise gets a null enterprise rather
			// than a scope error, so the missing scope is the most likely
			// cause and is worth naming first.
			return nil, fmt.Errorf(
				"enterprise %q is not visible to this token. This is most often a missing scope: "+
					"run `gh auth refresh -h %s -s read:enterprise`. If a GH_TOKEN environment variable is set, "+
					"it overrides your stored credentials and may lack that scope. "+
					"Otherwise check the slug from your enterprise URL, or pass --organization explicitly",
				slug, c.client.Host())
		}

		for _, node := range response.Enterprise.Organizations.Nodes {
			if node.Login != "" {
				logins = append(logins, node.Login)
			}
		}

		if !response.Enterprise.Organizations.PageInfo.HasNextPage {
			break
		}
		cursor = response.Enterprise.Organizations.PageInfo.EndCursor
	}

	sort.Strings(logins)
	return logins, nil
}

// listRepositories enumerates an organization's repositories together with
// their detected languages in a single GraphQL round trip per page. Fetching
// languages inline avoids one REST call per repository, which is the single
// largest saving available at organization scale.
func (c *Collector) listRepositories(ctx context.Context, org string) ([]apiRepository, error) {
	const query = `query($org:String!,$cursor:String){
  organization(login:$org){
    repositories(first:50,after:$cursor,orderBy:{field:PUSHED_AT,direction:DESC}){
      pageInfo{hasNextPage endCursor}
      nodes{
        name
        url
        isArchived
        isFork
        visibility
        pushedAt
        defaultBranchRef{name}
        pullRequests(first:1,orderBy:{field:UPDATED_AT,direction:DESC}){nodes{updatedAt}}
        languages(first:100){pageInfo{hasNextPage} nodes{name}}
      }
    }
  }
}`

	var repositories []apiRepository
	cursor := ""
	for {
		var response struct {
			Organization *struct {
				Repositories struct {
					PageInfo struct {
						HasNextPage bool   `json:"hasNextPage"`
						EndCursor   string `json:"endCursor"`
					} `json:"pageInfo"`
					Nodes []struct {
						apiRepository
						PushedAt     *string `json:"pushedAt"`
						PullRequests struct {
							Nodes []struct {
								UpdatedAt *string `json:"updatedAt"`
							} `json:"nodes"`
						} `json:"pullRequests"`
					} `json:"nodes"`
				} `json:"repositories"`
			} `json:"organization"`
		}

		variables := map[string]any{"org": org, "cursor": (*string)(nil)}
		if cursor != "" {
			variables["cursor"] = cursor
		}

		if err := c.client.GraphQL(ctx, query, variables, &response); err != nil {
			return nil, fmt.Errorf("listing repositories for %s: %w", org, err)
		}
		if response.Organization == nil {
			return nil, fmt.Errorf("organization %q was not found or is not visible to this token", org)
		}

		for _, node := range response.Organization.Repositories.Nodes {
			repo := node.apiRepository
			if node.PushedAt != nil {
				if parsed, err := time.Parse(time.RFC3339, *node.PushedAt); err == nil {
					repo.PushedAt = &parsed
					repo.LastActivityAt = &parsed
				}
			}
			// A pull request updated more recently than the last push still
			// counts as activity for the purposes of scan scheduling.
			for _, pull := range node.PullRequests.Nodes {
				if pull.UpdatedAt == nil {
					continue
				}
				parsed, err := time.Parse(time.RFC3339, *pull.UpdatedAt)
				if err != nil {
					continue
				}
				if repo.LastActivityAt == nil || parsed.After(*repo.LastActivityAt) {
					repo.LastActivityAt = &parsed
				}
			}

			// The languages connection is capped. On the rare repository that
			// exceeds it, fall back to REST rather than let a supported
			// language go unseen and report coverage as complete.
			if repo.Languages.PageInfo.HasNextPage {
				if names, err := c.repositoryLanguages(ctx, org, repo.Name); err == nil {
					repo.Languages.Nodes = names
				}
			}

			repositories = append(repositories, repo)
		}

		if !response.Organization.Repositories.PageInfo.HasNextPage {
			break
		}
		cursor = response.Organization.Repositories.PageInfo.EndCursor
	}

	return repositories, nil
}

// repositoryLanguages reads the full language list for a repository from REST.
// The endpoint returns every language Linguist detected, with no pagination,
// so it is the authoritative source when the GraphQL connection is truncated.
func (c *Collector) repositoryLanguages(ctx context.Context, org, name string) ([]struct {
	Name string `json:"name"`
}, error) {
	languages := map[string]int{}
	path := fmt.Sprintf("repos/%s/%s/languages", url.PathEscape(org), url.PathEscape(name))
	if err := c.client.GetJSON(ctx, path, &languages); err != nil {
		return nil, err
	}

	names := make([]struct {
		Name string `json:"name"`
	}, 0, len(languages))
	for language := range languages {
		names = append(names, struct {
			Name string `json:"name"`
		}{Name: language})
	}
	sort.Slice(names, func(i, j int) bool { return names[i].Name < names[j].Name })
	return names, nil
}

// getRepository fetches a single repository plus its languages via REST, used
// for --repository scope where GraphQL enumeration is unnecessary.
func (c *Collector) getRepository(ctx context.Context, org, name string) (apiRepository, error) {
	var rest restRepository
	if err := c.client.GetJSON(ctx, fmt.Sprintf("repos/%s/%s", org, name), &rest); err != nil {
		return apiRepository{}, fmt.Errorf("reading repository %s/%s: %w", org, name, err)
	}

	repo := apiRepository{
		Name:           rest.Name,
		URL:            rest.HTMLURL,
		IsArchived:     rest.Archived,
		IsFork:         rest.Fork,
		Visibility:     strings.ToUpper(rest.Visibility),
		PushedAt:       rest.PushedAt,
		LastActivityAt: rest.PushedAt,
	}
	if rest.DefaultBranch != "" {
		repo.DefaultBranchRef = &struct {
			Name string `json:"name"`
		}{Name: rest.DefaultBranch}
	}

	// A failure here must not be swallowed. Without language evidence an
	// exhausted rate limit is indistinguishable from an empty repository, and
	// the scan would report "not applicable" on a report still marked
	// complete.
	names, err := c.repositoryLanguages(ctx, org, name)
	if err != nil {
		return apiRepository{}, fmt.Errorf("reading languages for %s/%s: %w", org, name, err)
	}
	repo.Languages.Nodes = names

	return repo, nil
}

// configurationIndex maps repository name to its security configuration
// attachment state for one organization.
type configurationIndex struct {
	// byRepo holds the configuration name and attachment status per repository.
	byRepo map[string]repoConfiguration
	// filterNames records the configuration the user asked to filter on, when
	// --security-configuration was supplied.
	filterMatched map[string]bool
	filterActive  bool
}

type repoConfiguration struct {
	ConfigurationName string
	Status            string
}

// loadConfigurations reads every code security configuration in an
// organization and the repositories attached to each one.
//
// Cost is proportional to the number of configurations, not repositories, so
// this is cheap even for very large organizations. It is also the only source
// of "failed to attach" state, which surfaces rollouts that silently stopped.
func (c *Collector) loadConfigurations(ctx context.Context, org, filterName string) (*configurationIndex, error) {
	index := &configurationIndex{
		byRepo:        map[string]repoConfiguration{},
		filterMatched: map[string]bool{},
	}

	var configurations []securityConfiguration
	path := fmt.Sprintf("orgs/%s/code-security/configurations?per_page=100&target_type=all", url.PathEscape(org))
	err := c.client.GetPaginatedJSON(ctx, path, func(page []byte) error {
		var batch []securityConfiguration
		if err := json.Unmarshal(page, &batch); err != nil {
			return err
		}
		configurations = append(configurations, batch...)
		return nil
	})
	if err != nil {
		// Configuration APIs are unavailable on older GitHub Enterprise Server
		// releases. Degrade to default-setup-only reporting rather than
		// failing the whole scan.
		if ghapi.IsNotFound(err) || ghapi.IsForbidden(err) {
			return index, errConfigurationsUnavailable
		}
		return index, err
	}

	matchedFilter := false
	for _, configuration := range configurations {
		if filterName != "" && !strings.EqualFold(configuration.Name, filterName) {
			continue
		}
		if filterName != "" {
			matchedFilter = true
		}

		reposPath := fmt.Sprintf("orgs/%s/code-security/configurations/%d/repositories?per_page=100&status=all",
			url.PathEscape(org), configuration.ID)
		err := c.client.GetPaginatedJSON(ctx, reposPath, func(page []byte) error {
			var batch []configurationRepository
			if err := json.Unmarshal(page, &batch); err != nil {
				return err
			}
			for _, item := range batch {
				name := item.Repository.Name
				if name == "" {
					continue
				}
				// A repository can appear under several configurations over
				// time; prefer whichever entry reports a problem so failures
				// are never masked by a healthy-looking duplicate.
				existing, seen := index.byRepo[name]
				if !seen || attachmentPriority(item.Status) < attachmentPriority(existing.Status) {
					index.byRepo[name] = repoConfiguration{
						ConfigurationName: configuration.Name,
						Status:            item.Status,
					}
				}
				if filterName != "" {
					index.filterMatched[name] = true
				}
			}
			return nil
		})
		if err != nil {
			return index, fmt.Errorf("listing repositories for configuration %q in %s: %w", configuration.Name, org, err)
		}
	}

	if filterName != "" && !matchedFilter {
		return index, fmt.Errorf("security configuration %q was not found in organization %s", filterName, org)
	}

	// Only enable filtering once the configuration data has been read
	// successfully, so a failed load can never exclude every repository.
	index.filterActive = filterName != ""

	return index, nil
}

// attachmentPriority ranks attachment states so problems win over successes
// when a repository appears more than once.
func attachmentPriority(status string) int {
	switch strings.ToLower(status) {
	case "failed":
		return 0
	case "updating":
		return 1
	case "attaching":
		return 2
	case "enforced":
		return 3
	case "attached":
		return 4
	default:
		return 5
	}
}

// loadProperties reads custom property values for every repository in an
// organization in bulk. Custom properties are how customers map repositories
// onto applications, so this powers the grouping used in reports.
func (c *Collector) loadProperties(ctx context.Context, org string) (map[string]map[string]string, error) {
	values := map[string]map[string]string{}
	path := fmt.Sprintf("orgs/%s/properties/values?per_page=100", url.PathEscape(org))

	err := c.client.GetPaginatedJSON(ctx, path, func(page []byte) error {
		var batch []propertyValues
		if err := json.Unmarshal(page, &batch); err != nil {
			return err
		}
		for _, item := range batch {
			if item.RepositoryName == "" {
				continue
			}
			properties := map[string]string{}
			for _, property := range item.Properties {
				properties[property.PropertyName] = formatPropertyValue(property.Value)
			}
			values[item.RepositoryName] = properties
		}
		return nil
	})
	if err != nil {
		if ghapi.IsNotFound(err) || ghapi.IsForbidden(err) {
			return values, errPropertiesUnavailable
		}
		return values, err
	}

	return values, nil
}

// formatPropertyValue renders a custom property value as a string. Multi-select
// properties arrive as arrays and are joined for display and filtering.
func formatPropertyValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case float64:
		return strings.TrimSuffix(strings.TrimRight(fmt.Sprintf("%f", typed), "0"), ".")
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			parts = append(parts, formatPropertyValue(item))
		}
		return strings.Join(parts, ", ")
	default:
		return fmt.Sprintf("%v", typed)
	}
}
