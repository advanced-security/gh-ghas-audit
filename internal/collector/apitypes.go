package collector

import "time"

// This file contains the GitHub API response shapes the collector consumes.
// Only the fields the report depends on are modelled, so unrelated API changes
// do not break decoding.

// apiRepository is a repository as returned by GraphQL enumeration.
type apiRepository struct {
	Name             string `json:"name"`
	URL              string `json:"url"`
	IsArchived       bool   `json:"isArchived"`
	IsFork           bool   `json:"isFork"`
	Visibility       string `json:"visibility"`
	PushedAt         *time.Time
	DefaultBranchRef *struct {
		Name string `json:"name"`
	} `json:"defaultBranchRef"`
	Languages struct {
		Nodes []struct {
			Name string `json:"name"`
		} `json:"nodes"`
	} `json:"languages"`
}

// restRepository is a repository as returned by the REST repos endpoints. It
// is used for single-repository scope and as a fallback when GraphQL
// enumeration is unavailable.
type restRepository struct {
	Name          string     `json:"name"`
	FullName      string     `json:"full_name"`
	HTMLURL       string     `json:"html_url"`
	Archived      bool       `json:"archived"`
	Fork          bool       `json:"fork"`
	Visibility    string     `json:"visibility"`
	Private       bool       `json:"private"`
	DefaultBranch string     `json:"default_branch"`
	PushedAt      *time.Time `json:"pushed_at"`
	Owner         struct {
		Login string `json:"login"`
	} `json:"owner"`
}

// defaultSetup mirrors GET /repos/{owner}/{repo}/code-scanning/default-setup.
type defaultSetup struct {
	State       string     `json:"state"`
	Languages   []string   `json:"languages"`
	QuerySuite  string     `json:"query_suite"`
	ThreatModel string     `json:"threat_model"`
	UpdatedAt   *time.Time `json:"updated_at"`
	Schedule    string     `json:"schedule"`
	RunnerType  string     `json:"runner_type"`
	RunnerLabel string     `json:"runner_label"`
}

// workflowList mirrors GET /repos/{owner}/{repo}/actions/workflows.
type workflowList struct {
	TotalCount int `json:"total_count"`
	Workflows  []struct {
		ID    int64  `json:"id"`
		Name  string `json:"name"`
		Path  string `json:"path"`
		State string `json:"state"`
	} `json:"workflows"`
}

// workflowRunList mirrors the Actions workflow runs endpoints.
type workflowRunList struct {
	TotalCount  int           `json:"total_count"`
	WorkflowRun []workflowRun `json:"workflow_runs"`
}

type workflowRun struct {
	ID           int64      `json:"id"`
	Name         string     `json:"name"`
	Path         string     `json:"path"`
	Status       string     `json:"status"`
	Conclusion   string     `json:"conclusion"`
	Event        string     `json:"event"`
	HeadBranch   string     `json:"head_branch"`
	HeadSHA      string     `json:"head_sha"`
	RunAttempt   int        `json:"run_attempt"`
	RunStartedAt *time.Time `json:"run_started_at"`
	CreatedAt    *time.Time `json:"created_at"`
	UpdatedAt    *time.Time `json:"updated_at"`
	HTMLURL      string     `json:"html_url"`
}

// jobList mirrors GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs.
type jobList struct {
	TotalCount int   `json:"total_count"`
	Jobs       []job `json:"jobs"`
}

type job struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	Status      string     `json:"status"`
	Conclusion  string     `json:"conclusion"`
	StartedAt   *time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
	HTMLURL     string     `json:"html_url"`
	Steps       []struct {
		Name       string `json:"name"`
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
		Number     int    `json:"number"`
	} `json:"steps"`
}

// codeqlDatabase mirrors GET /repos/{owner}/{repo}/code-scanning/codeql/databases.
// A database is durable proof that extraction and upload succeeded for a
// language, which is stronger evidence than a green workflow conclusion.
type codeqlDatabase struct {
	ID        int64      `json:"id"`
	Name      string     `json:"name"`
	Language  string     `json:"language"`
	CreatedAt *time.Time `json:"created_at"`
	UpdatedAt *time.Time `json:"updated_at"`
}

// codeScanningAnalysis mirrors an entry from the code scanning analyses
// endpoint. The error field names the language that failed without needing to
// read Actions logs.
type codeScanningAnalysis struct {
	Category   string     `json:"category"`
	Error      string     `json:"error"`
	CreatedAt  *time.Time `json:"created_at"`
	Results    int        `json:"results_count"`
	Rules      int        `json:"rules_count"`
	CommitSHA  string     `json:"commit_sha"`
	Ref        string     `json:"ref"`
	Deletable  bool       `json:"deletable"`
	AnalysisID int64      `json:"id"`
}

// securityConfiguration mirrors an org or enterprise code security
// configuration.
type securityConfiguration struct {
	ID                       int64  `json:"id"`
	Name                     string `json:"name"`
	TargetType               string `json:"target_type"`
	Enforcement              string `json:"enforcement"`
	CodeScanningDefaultSetup string `json:"code_scanning_default_setup"`
}

// configurationRepository mirrors an entry from the configuration
// repositories endpoint. The status field exposes rollout failures that
// default setup alone never reveals.
type configurationRepository struct {
	Status     string `json:"status"`
	Repository struct {
		Name     string `json:"name"`
		FullName string `json:"full_name"`
	} `json:"repository"`
}

// propertyValues mirrors GET /orgs/{org}/properties/values.
type propertyValues struct {
	RepositoryName string `json:"repository_name"`
	Properties     []struct {
		PropertyName string `json:"property_name"`
		Value        any    `json:"value"`
	} `json:"properties"`
}
