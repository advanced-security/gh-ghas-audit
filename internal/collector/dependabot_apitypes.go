package collector

import "time"

// This file contains the GitHub API response shapes the Dependabot/SCA health
// collector consumes. Only the fields the report depends on are modelled, so
// unrelated API changes do not break decoding. It is kept separate from
// apitypes.go (code scanning) because the two collectors share no response
// shapes.

// dependabotRestRepository is a repository as returned by REST, including the
// permission-gated security_and_analysis block. A separate struct from
// restRepository is used deliberately: the two collectors decode different
// fields from the same endpoint and must not be coupled to each other's needs.
type dependabotRestRepository struct {
	Name          string     `json:"name"`
	FullName      string     `json:"full_name"`
	HTMLURL       string     `json:"html_url"`
	Archived      bool       `json:"archived"`
	Fork          bool       `json:"fork"`
	Visibility    string     `json:"visibility"`
	DefaultBranch string     `json:"default_branch"`
	PushedAt      *time.Time `json:"pushed_at"`
	Owner         struct {
		Login string `json:"login"`
	} `json:"owner"`
	// SecurityAndAnalysis is only populated for callers with admin, owner or
	// security-manager access. Its absence must be read as "unknown", not
	// "disabled".
	SecurityAndAnalysis *struct {
		DependabotSecurityUpdates *struct {
			Status string `json:"status"`
		} `json:"dependabot_security_updates"`
	} `json:"security_and_analysis"`
}

// contentsFile mirrors GET /repos/{owner}/{repo}/contents/{path} for a single
// file (as opposed to a directory listing).
type contentsFile struct {
	Type     string `json:"type"`
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
	Name     string `json:"name"`
	Path     string `json:"path"`
}

// contentsEntry is one entry of a directory listing from the same endpoint.
type contentsEntry struct {
	Type string `json:"type"`
	Name string `json:"name"`
	Path string `json:"path"`
}

// dependabotYAML mirrors the subset of .github/dependabot.yml this collector
// reads. Unknown keys are ignored by the YAML decoder.
type dependabotYAML struct {
	Version    int                           `yaml:"version"`
	Registries map[string]dependabotRegistry `yaml:"registries"`
	Updates    []dependabotUpdateBlock       `yaml:"updates"`
}

type dependabotRegistry struct {
	Type string `yaml:"type"`
}

type dependabotUpdateBlock struct {
	PackageEcosystem      string   `yaml:"package-ecosystem"`
	Directory             string   `yaml:"directory"`
	Directories           []string `yaml:"directories"`
	TargetBranch          string   `yaml:"target-branch"`
	OpenPullRequestsLimit *int     `yaml:"open-pull-requests-limit"`
	Registries            []string `yaml:"registries"`
}

// dependencyGraphManifestsResponse mirrors the GraphQL
// Repository.dependencyGraphManifests connection.
type dependencyGraphManifestsResponse struct {
	Repository *struct {
		DependencyGraphManifests struct {
			TotalCount int `json:"totalCount"`
			PageInfo   struct {
				HasNextPage bool   `json:"hasNextPage"`
				EndCursor   string `json:"endCursor"`
			} `json:"pageInfo"`
			Nodes []dependencyGraphManifestNode `json:"nodes"`
		} `json:"dependencyGraphManifests"`
	} `json:"repository"`
}

type dependencyGraphManifestNode struct {
	ID                string `json:"id"`
	Filename          string `json:"filename"`
	Parseable         bool   `json:"parseable"`
	ExceedsMaxSize    bool   `json:"exceedsMaxSize"`
	DependenciesCount int    `json:"dependenciesCount"`
	Dependencies      struct {
		PageInfo struct {
			HasNextPage bool   `json:"hasNextPage"`
			EndCursor   string `json:"endCursor"`
		} `json:"pageInfo"`
		Nodes []struct {
			Relationship string `json:"relationship"`
		} `json:"nodes"`
	} `json:"dependencies"`
}

// manifestDependenciesPageResponse mirrors a follow-up query re-fetching a
// single DependencyGraphManifest by its node ID (it implements GraphQL's
// Node interface), used to page past the initial dependencies(first:100)
// sample when a manifest has more dependencies than that and none of the
// inspected ones were transitive. Unlike the bulk dependencyGraphManifests
// query, this is only ever issued for the rare manifest that actually needs
// it, so its cost is bounded by the number of such manifests, not by total
// dependency count across the repository.
type manifestDependenciesPageResponse struct {
	Node *struct {
		Dependencies struct {
			PageInfo struct {
				HasNextPage bool   `json:"hasNextPage"`
				EndCursor   string `json:"endCursor"`
			} `json:"pageInfo"`
			Nodes []struct {
				Relationship string `json:"relationship"`
			} `json:"nodes"`
		} `json:"dependencies"`
	} `json:"node"`
}

// vulnerabilityAlertsPullRequestsResponse mirrors the GraphQL
// Repository.vulnerabilityAlerts connection, read for its
// dependabotUpdate.pullRequest linkage (the authoritative way to identify a
// Dependabot security update pull request) and, as a secondary signal, the
// vulnerable package name of alerts that never got such a link (see
// collectSecurityUpdatePullRequestNumbers).
type vulnerabilityAlertsPullRequestsResponse struct {
	Repository *struct {
		VulnerabilityAlerts struct {
			PageInfo struct {
				HasNextPage bool   `json:"hasNextPage"`
				EndCursor   string `json:"endCursor"`
			} `json:"pageInfo"`
			Nodes []vulnerabilityAlertPullRequestNode `json:"nodes"`
		} `json:"vulnerabilityAlerts"`
	} `json:"repository"`
}

type vulnerabilityAlertPullRequestNode struct {
	// State is the alert's own state (OPEN, DISMISSED, FIXED or
	// AUTO_DISMISSED). Filtering to only trustworthy, still-relevant alerts
	// already happens at the query level (see the states:[OPEN,
	// AUTO_DISMISSED] filter on collectSecurityUpdatePullRequestNumbers's
	// GraphQL query): FIXED and explicitly DISMISSED alerts are never
	// fetched in the first place, so this field is not read anywhere in the
	// collector today. It is kept on the response shape only in case a
	// future caller needs to distinguish OPEN from AUTO_DISMISSED among the
	// alerts that are fetched.
	State                 string `json:"state"`
	SecurityVulnerability *struct {
		Package *struct {
			Name string `json:"name"`
		} `json:"package"`
	} `json:"securityVulnerability"`
	DependabotUpdate *struct {
		PullRequest *struct {
			Number int    `json:"number"`
			State  string `json:"state"`
		} `json:"pullRequest"`
	} `json:"dependabotUpdate"`
}

// dependabotAlert mirrors an entry from GET
// /repos/{owner}/{repo}/dependabot/alerts.
type dependabotAlert struct {
	State            string     `json:"state"`
	CreatedAt        *time.Time `json:"created_at"`
	SecurityAdvisory struct {
		Severity string `json:"severity"`
		// Classification is "general" for an ordinary vulnerability
		// advisory, or "malware" when the advisory instead flags a
		// dependency that is itself malicious.
		Classification string `json:"classification"`
	} `json:"security_advisory"`
}

// sbomResponse mirrors the fields this collector needs from GET
// /repos/{owner}/{repo}/dependency-graph/sbom. Unlike
// dependencyGraphManifestsResponse, this is a single repo-wide SPDX document
// with no per-manifest breakdown; it is consulted only for
// creationInfo.creators, which names the tool(s) that populated the graph
// and is the only place GitHub exposes that (there is no equivalent field on
// GraphQL's DependencyGraphManifest).
type sbomResponse struct {
	SBOM struct {
		CreationInfo struct {
			Creators []string `json:"creators"`
		} `json:"creationInfo"`
	} `json:"sbom"`
}

// pullRequest mirrors the fields this collector needs from GET
// /repos/{owner}/{repo}/pulls.
type pullRequest struct {
	Number    int        `json:"number"`
	Title     string     `json:"title"`
	Body      string     `json:"body"`
	CreatedAt *time.Time `json:"created_at"`
	User      struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"user"`
	Head struct {
		SHA string `json:"sha"`
		Ref string `json:"ref"`
	} `json:"head"`
	Labels []struct {
		Name string `json:"name"`
	} `json:"labels"`
}

// combinedStatus mirrors GET /repos/{owner}/{repo}/commits/{ref}/status.
// This only reflects statuses posted through the (legacy) Statuses API; it
// does not reflect Checks API results, which is what GitHub Actions (and
// most modern third-party CI) actually posts. See checkRunsResponse, which
// must also be consulted to detect an Actions-based CI failure.
type combinedStatus struct {
	State string `json:"state"`
}

// checkRunsResponse mirrors GET
// /repos/{owner}/{repo}/commits/{ref}/check-runs.
type checkRunsResponse struct {
	CheckRuns []struct {
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
	} `json:"check_runs"`
}

// branchRules mirrors GET /repos/{owner}/{repo}/rules/branches/{branch}: the
// effective rules for a branch, merged across repository, organization and
// enterprise rulesets. Only the required_status_checks rule type is modelled;
// there is no native "dependency review" rule type, so enforcement is always
// detected as a pattern match against a required status check context.
type branchRule struct {
	Type       string `json:"type"`
	Parameters struct {
		RequiredStatusChecks []struct {
			Context string `json:"context"`
		} `json:"required_status_checks"`
	} `json:"parameters"`
}

// classicRequiredStatusChecks mirrors GET
// /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks,
// the older, separate branch-protection system that predates rulesets.
// GET /repos/{owner}/{repo}/rules/branches/{branch} (branchRule above) only
// returns rules from the newer Rulesets feature; a repository enforcing a
// required status check purely through classic branch protection is
// invisible to that endpoint, so this one must also be checked.
type classicRequiredStatusChecks struct {
	Contexts []string `json:"contexts"`
	Checks   []struct {
		Context string `json:"context"`
	} `json:"checks"`
}

// dependabotSecretList mirrors GET /orgs/{org}/dependabot/secrets and
// /repos/{owner}/{repo}/dependabot/secrets.
type dependabotSecretList struct {
	TotalCount int `json:"total_count"`
	Secrets    []struct {
		Name string `json:"name"`
	} `json:"secrets"`
}
