# GitHub CLI ghas-audit extension

GHAS Audit is a GitHub CLI extension that audits your GitHub Advanced Security (GHAS) code scanning setup for one or more organizations and repositories. It checks if the default code scanning configuration is enabled and lists the languages detected in your repositories.

## Summary

GHAS Audit helps you:

- Verify if code scanning with Default setup is properly enabled on your repositories.
- Get a summary of the languages used in each repository.
- Identify which languages may not be configured with default code scanning.
- Export the audit results either as a formatted table in the terminal or as a CSV file.

## How It Works

1. **Initialization:** The tool connects to GitHub via the gh CLI API.
2. **Data Gathering:** It fetches the list of repositories for a given organization (or a single repository if specified) and retrieves:
   - Language breakdown using the GitHub repository [languages API endpoint](https://docs.github.com/en/enterprise-cloud@latest/rest/repos/repos?apiVersion=2022-11-28#list-repository-languages).
   - Default setup configuration using GitHub's [code scanning default setup API endpoints](https://docs.github.com/en/enterprise-cloud@latest/rest/code-scanning/code-scanning?apiVersion=2022-11-28#get-a-code-scanning-default-setup-configuration).
3. **Processing:** Each repository is processed to determine if code scanning is enabled, the list of normalized languages detected, and any languages not configured.
4. **Reporting:** The results are compiled into a report:
   - **Terminal Output:** Displays a formatted table.
   - **CSV Output:** Exports results to a specified CSV file.

## Prerequisites

- **GitHub CLI (gh):** Install from [GitHub CLI](https://cli.github.com/).
- **gh Extension Support:** Ensure your gh CLI version supports extensions.
- [GHAS](https://docs.github.com/en/enterprise-cloud@latest/get-started/learning-about-github/about-github-advanced-security) enabled on your organization or repository.

## Installation

### Remote Installation

You can install the extension directly from the repository:

```bash
gh extension install advanced-security/gh-ghas-audit
```

### Local Installation

Clone the repository, build the tool, and install locally:

```bash
git clone https://github.com/advanced-security/gh-ghas-audit.git
cd gh-ghas-audit
go mod download
go build -o gh-ghas-audit .
gh extension install .
```

## Usage

Run the ghas-audit command using the gh CLI.

```bash
gh ghas-audit code-scanning --help
Audit your code scanning setup

Usage:
  gh-ghas-audit code-scanning [flags]

Flags:
  -h, --help   help for code-scanning

Global Flags:
      --csv-output string      File path to output CSV report
  -o, --organizations string   Comma separated list of organizations to audit
  -r, --repository string      Single repository to audit
```

### Terminal Output

```bash
gh ghas-audit code-scanning -o my-org
```

### CSV Output

```bash
gh ghas-audit code-scanning -o my-org --csv-output audit-report.csv
```

### Example Usages

#### Example Terminal Output

```
$ gh ghas-audit code-scanning -o my-demo-org
Starting audit...
Processing organization: my-demo-org
Found 3 repositories in my-demo-org
 - Processing repository: repo-alpha [1/3]
 - Processing repository: repo-beta [2/3]
 - Processing repository: repo-gamma [3/3]
Finished processing organization: my-demo-org

Organization    Repository   Default setup enabled?   Languages in repo       Default setup configured  Not configured (supported languages)
my-demo-org     repo-alpha   Enabled                  Go, JavaScript          Go, JavaScript            -
my-demo-org     repo-beta    Disabled                 Python                  -                        Python
my-demo-org     repo-gamma   GHAS is not enabled      Unknown                 Unknown                  Unknown

Audit complete!
```

#### Example CSV Output

```bash
$ gh ghas-audit code-scanning -o my-demo-org --csv-output audit-report.csv
Starting audit...
CSV output enabled. Writing to audit-report.csv
Processing organization: my-demo-org
Found 3 repositories in my-demo-org
 - Processing repository: repo-alpha [1/3]
 - Processing repository: repo-beta [2/3]
 - Processing repository: repo-gamma [3/3]
Finished processing organization: my-demo-org
Audit complete!
```

The CSV file audit-report.csv will contain:

```csv
Organization,Repository,Default setup enabled?,Languages in repo,Default setup configured,Not configured (supported languages)
my-demo-org,repo-alpha,Enabled,Go, JavaScript,Go, JavaScript,-
my-demo-org,repo-beta,Disabled,Python,-,Python
my-demo-org,repo-gamma,GHAS is not enabled,Unknown,Unknown,Unknown
```
