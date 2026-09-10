# gh-ghas-audit GitHub CLI extension

A [GitHub CLI][gh-cli] extension reporting code scanning health across organizations and enterprises.

Default setup can be enabled at scale, but there is no org-level view of whether scans actually succeed. A repository can look protected while its analysis silently fails, never runs, stops running, or skips a language.

## Contents

- [What it reports](#what-it-reports)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Scan depth](#scan-depth)
- [Status dimensions](#status-dimensions)
- [Filtering and grouping](#filtering-and-grouping)
- [Output formats](#output-formats)
- [Scheduled reporting](#scheduled-reporting)
- [Permissions](#permissions)
- [Performance and rate limits](#performance-and-rate-limits)
- [Deep diagnostics](#deep-diagnostics)
- [Known limitations](#known-limitations)
- [Upgrading from 1.x](#upgrading-from-1x)
- [Legacy command](#legacy-command)

## What it reports

Per repository in scope:

- Default setup configured, and whether a security configuration **failed to attach**.
- Whether the latest run succeeded, failed, is running, or **never completed**.
- Whether the managed CodeQL workflow is **disabled** (GitHub does this automatically after inactivity).
- **When it last scanned successfully**, against a freshness threshold.
- **Which languages are actually analyzed**, versus present in the repository and versus configured.
- **Languages silently dropped from default setup** after a failed analysis. Nothing else in the product surfaces this.
- Languages CodeQL **cannot** analyze, such as Scala.
- Links to the run and per-language job as evidence.

## Installation

```bash
gh extension install advanced-security/gh-ghas-audit
```

From source:

```bash
git clone https://github.com/advanced-security/gh-ghas-audit.git
cd gh-ghas-audit && go build -o gh-ghas-audit . && gh extension install .
```

## Quick start

```bash
gh ghas-audit code-scanning status --organization my-org
gh ghas-audit code-scanning status --enterprise my-enterprise
gh ghas-audit code-scanning status -o my-org --status failing,stalled,stale --detailed
```

```text
Code scanning status: my-org
42 repositories, 6 needing attention, scans older than 8d are stale

  failing          2
  stalled          3
  stale            1
  degraded         1
  healthy         28
  not-configured   4
  not-applicable   3

HEALTH    REPOSITORY         CONFIG      EXECUTION    LAST SCAN     LANGUAGES
failing   my-org/payments    configured  failure      12 days ago   1/2 (not analyzed: java-kotlin)
stalled   my-org/checkout    configured  no-workflow  never         0/1 (not analyzed: go)
stale     my-org/legacy-api  configured  success      41 days ago   2/2
degraded  my-org/web         configured  success      2 days ago    1/2 (not configured: python)
healthy   my-org/identity    configured  success      1 day ago     3/3
```

## Scan depth

`--scan-depth` selects how much evidence is gathered. Each level adds a kind of
evidence and closes a specific blind spot, so it is a scope control, not a
quality dial.

| Depth | Adds | Cost per repository | Blind spot |
| --- | --- | --- | --- |
| `config` | default setup and repository languages | ~2 requests | no runtime evidence, so it never reports `healthy` |
| `health` (default) | workflows, runs, jobs, analyses, CodeQL databases | ~5 requests | cannot see log-only warnings |
| `diagnostics` | Actions log parsing | megabytes, uncached | best effort; depends on log retention |

```bash
gh ghas-audit code-scanning status -o my-org --scan-depth config
gh ghas-audit code-scanning status -o my-org
gh ghas-audit code-scanning status -o my-org --scan-depth diagnostics
```

`config` answers the rollout question cheaply: which supported languages are
not configured for analysis. Because it reads no runtime evidence it reports
`unknown` rather than `healthy`, and it cannot recognize advanced setup.

`low`, `medium` and `high` are accepted as aliases.

## Status dimensions

Every repository is reported across four independent dimensions.

| Dimension | Values | Question |
| --- | --- | --- |
| `configuration` | `configured`, `not-configured`, `advanced-setup`, `attaching`, `updating`, `attach-failed`, `unavailable` | Is it set up, and did the security configuration attach? |
| `execution` | `success`, `failure`, `timed-out`, `cancelled`, `action-required`, `startup-failure`, `in-progress`, `queued`, `no-workflow`, `no-completed-run` | Did the latest run succeed, fail, or never run? |
| `freshness` | `current`, `stale`, `never-scanned` | How long since it last scanned successfully? |
| `coverage` | `complete`, `partial`, `gap`, `no-supported-languages` | Are all supported languages analyzed? |

These roll up into one `overall` severity, in precedence order:

| Severity | Meaning |
| --- | --- |
| `failing` | Latest run failed, timed out, or was cancelled. |
| `stalled` | Configured but not running: no workflow, no completed run, or attachment failed. |
| `stale` | Succeeded, but not within the freshness threshold. |
| `degraded` | Succeeded, but a language is unanalyzed or unconfigured, or a warning was found. |
| `in-progress` | A run is executing, or a configuration is attaching. |
| `healthy` | Configured, current, fully covered. |
| `not-configured` | Not enabled, and CodeQL-analyzable code is present. |
| `not-applicable` | Nothing CodeQL can analyze. |
| `unavailable` | Could not be inspected, usually code security not enabled. |

`stalled` is separated from `failing` because a configured repository with no completed run looks green everywhere else. `not-applicable` is separated from `not-configured` so empty repositories do not bury real failures.

### Languages dropped after a failed analysis

When a language's analysis fails, GitHub clears it from default setup and it is never scanned again. Repository languages are normalized onto CodeQL identifiers and compared with configured languages:

| Repository contains | Normalizes to | Configured | Result |
| --- | --- | --- | --- |
| Kotlin | `java-kotlin` | `c-cpp` only | not being scanned |
| TypeScript | `javascript-typescript` | `javascript-typescript` | covered |
| Scala | not supported | n/a | CodeQL cannot analyze it |

| Evidence | Reported as | Fix |
| --- | --- | --- |
| Detected, not configured, no analysis job | `language-not-configured` (warning) | Enable the language |
| Detected, not configured, failed analysis job | `language-auto-deselected` (error) | Re-enable it **and** fix the failure |

Both appear in `missing_languages`; dropped ones also in `deselected_languages` and the `Languages dropped after failing` CSV column.

## Filtering and grouping

| Scope flag | Purpose |
| --- | --- |
| `--organization`, `-o` | One or more organizations, comma separated. |
| `--enterprise`, `-e` | Every organization in an enterprise. |
| `--repository`, `-r` | A single `OWNER/REPO`. |

| Narrowing flag | Purpose |
| --- | --- |
| `--status` | Only these overall statuses. |
| `--language` | Only repositories involving these CodeQL languages. |
| `--visibility` | Only `public`, `private` or `internal`. |
| `--match`, `--exclude` | Glob patterns on repository name. |
| `--skip-archived`, `--skip-forks` | Exclude archived or forked repositories. |
| `--security-configuration` | Only repositories attached to a named configuration. |
| `--property-filter` | Custom property match, as `NAME=VALUE`. |
| `--activity` | Only `active` or `inactive`. |
| `--stale-after` | Freshness threshold, active repositories. Default `8d`. |
| `--stale-after-inactive` | Freshness threshold, inactive repositories. Default `32d`. |
| `--inactive-after` | Time without a push that marks a repository inactive. Default `180d`. |

`--match`, `--exclude`, `--visibility` and `--property-filter` apply before any per-repository request, so excluded repositories cost nothing.

### Freshness and activity

GitHub scans weekly, except repositories with no pushes or pull requests for six months, which scan monthly when the organization enables that setting ([changelog](https://github.blog/changelog/2026-06-09-periodic-code-scanning-of-inactive-repositories/)). Two thresholds are therefore applied:

| Flag | Default | Applies to |
| --- | --- | --- |
| `--stale-after` | `8d` | Active repositories |
| `--stale-after-inactive` | `32d` | Inactive repositories |
| `--inactive-after` | `180d` | Push age that marks a repository inactive |

Each row reports which threshold was applied:

```text
HEALTH  REPOSITORY   LAST SCAN               DETAIL
stale   org/Infinity 204 days ago (inactive) no successful analysis within 32d (inactive)
stale   org/Web      20 days ago             no successful analysis within 8d
```

```bash
gh ghas-audit code-scanning status -o my-org --activity active --status stale,failing,stalled
gh ghas-audit code-scanning status -o my-org --activity inactive --status stale
```

Activity is inferred from push and pull request timestamps, an approximation of GitHub's own rule. The organization's monthly-scanning setting is not exposed by any API, so `--stale-after-inactive` is simply the threshold applied.

### Grouping by application

```bash
gh ghas-audit code-scanning status -o my-org --group-by-property application
```

```text
By application
  payments-platform                18 repositories, 4 needing attention
  identity                          9 repositories, 0 needing attention
  (not set)                        11 repositories, 2 needing attention
```

Property names match case-insensitively (`project` finds `Project`). Multi-select properties match on any value, so `--property-filter Project=Internal` selects a repository whose `Project` is `INFINITY, Internal`.

## Output formats

| Format | Use |
| --- | --- |
| `table` | Terminal review. Add `--detailed` for an explanation column. |
| `json` | Complete versioned report. The canonical data contract. |
| `ndjson` | Header record plus one record per repository, for streaming. |
| `csv` | One row per repository. |
| `language-csv` | One row per repository language. |

```bash
gh ghas-audit code-scanning status -o my-org --format csv --output status.csv
gh ghas-audit code-scanning status -o my-org --format language-csv --output languages.csv
gh ghas-audit code-scanning status -o my-org --format json --output status.json
```

Check `schema_version` before parsing and `stats.incomplete` before trusting the result:

```bash
jq -r '.repositories[] | select(.status.overall == "stalled") | .full_name' status.json
jq '.summary.by_severity' status.json
jq '.stats.incomplete' status.json
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Completed, nothing matched `--fail-on`. |
| `1` | The tool failed. |
| `2` | Completed and `--fail-on` matched. |

```bash
gh ghas-audit code-scanning status -o my-org --fail-on failing,stalled
```

## Scheduled reporting

Install the released extension in a workflow and invoke it; it is not packaged as an Action. A complete scheduled workflow with GitHub App auth, cache reuse, job summary and artifact upload is in [`examples/code-scanning-status.yml`](examples/code-scanning-status.yml).

## Permissions

Missing permissions produce `unavailable` rows rather than silent omissions, and set `stats.incomplete`.

| Capability | Requirement |
| --- | --- |
| Repository inventory and languages | Repository `Metadata: read` |
| Default setup and CodeQL databases | Repository `Code scanning alerts: read` |
| Workflow runs and jobs | Repository `Actions: read` |
| Security configurations and attachment | Organization `Administration: read` |
| Custom properties | Organization `Custom properties: read` |
| `--enterprise` discovery | Token with `read:enterprise` |

GitHub App installation tokens are scoped to one organization and cannot list an enterprise; run once per organization or use a scoped PAT. The Actions `GITHUB_TOKEN` cannot inventory an organization.

## Performance and rate limits

A configured repository costs roughly five REST requests. Inventory and languages come from GraphQL, one query per 50 repositories. Unconfigured repositories cost one request; filtered-out repositories cost nothing.

Measured against an eight-organization enterprise of 35 repositories:

| Run | REST requests | 304 cache hits | Rate limit consumed |
| --- | --- | --- | --- |
| Cold | 145 | 0 | 145 |
| Warm, same cache | 145 | 137 | 9 |

`304 Not Modified` does not count against the primary rate limit, so repeat scans cost almost nothing in quota. A warm run is not much faster in wall clock time; the saving is quota.

- Use a **GitHub App installation token** for large estates: higher limit, per-installation budget.
- Keep `--concurrency` moderate. The default of 8 is well below GitHub's ceiling; raising it risks secondary rate limits.
- Use `--cache-dir` on every run; `--refresh` only to discard deliberately.
- Narrow with `--match`, `--exclude` or `--property-filter`.

Primary and secondary rate limits are handled automatically, honouring `Retry-After` with jittered backoff. Waits appear in `stats.rate_limit_waits`.

## Deep diagnostics

At `--scan-depth diagnostics` the tool parses Actions logs for warning text no
API exposes.

```bash
gh ghas-audit code-scanning status -o my-org --scan-depth diagnostics
gh ghas-audit code-scanning status -o my-org --scan-depth diagnostics --deep-scope problematic
```

`--deep-scope` defaults to `all`. `problematic` inspects only repositories that
already look unhealthy, which is cheaper but can only explain a failure, never
discover one: a warning behind a green run is invisible to it.

- **Slow and rate limit heavy.** Each repository downloads a full log archive. Use an App installation token.
- **Best effort.** Findings are labelled `"source": "log"` and never presented as authoritative.
- **Bounded.** `--deep-diagnostics-max-repos` (default 200) and `--deep-diagnostics-max-mb` (default 32).

It parses the CodeQL diagnostic blocks the repository tool status page displays:

```text
##[group]Low C# analysis quality (1 result)
* Scanning C# code completed successfully, but the scan encountered issues ...
##[endgroup]
```

Severity follows how the page presents each entry:

| Status page | Reported as | Effect |
| --- | --- | --- |
| Error, e.g. failed build or no analyzable code | `error` | Failing or degraded |
| Warning, e.g. low analysis quality, duplicate classes | `warning` | Degraded |
| Suggestion, e.g. build-mode `none`, private registries | `info` | None |

Unrecognized entries are recorded as `info` with their original text. Routine noise such as deprecation notices is filtered out.

## Known limitations

These are limits of the public GitHub API, not of this tool.

- **No exact parity with the tool status page.** It has no REST or GraphQL endpoint. `--deep-diagnostics` reconstructs most of it from Actions logs, subject to log format and retention.
- **Coverage is inferred**, from per-language jobs and CodeQL databases, not declared.
- **`actions` cannot be detected from source**, so it is never reported as a coverage gap.
- **Advanced setup coverage is inferred from analyses.** Which languages an advanced workflow intended to scan lives in its YAML and no API exposes it, so a language present but never analyzed is reported as not configured, exactly as for default setup. Third-party SARIF is not evaluated.
- **`config` depth cannot recognize advanced setup**, because that needs the analyses endpoint.
- **Enterprise scans need an enterprise-scoped token.** See [Permissions](#permissions).
- **No push notification.** There is no webhook for analysis degradation; schedule this report.
- **A partial scan is marked, not hidden.** Repositories with unread evidence are never `healthy`: status carries `incomplete`, the `Evidence complete` CSV column is `false`, and `stats.incomplete` is `true`.
- **Rate limits are never reported as repository health.** Throttled requests are retried, then recorded as collection errors.

## Upgrading from 1.x

`code-scanning status` is new; the original `code-scanning` command still runs
and its CSV is unchanged. Two things to know if you move a pipeline onto
`status`:

**The CSV schema is different.** The original has 6 columns, `status` has 40.
Positional scripts (`cut -d, -f5`) will read the wrong field silently. Column
mapping:

| 1.x column | `status` equivalent | Value change |
| --- | --- | --- |
| `Default setup enabled?` | `Configuration status` | `Enabled`/`Disabled` → `configured`/`not-configured`/`advanced-setup`/`attach-failed`/`unavailable` |
| `Languages in repo` | `Detected languages` | aliases folded, so `typescript` is no longer emitted next to `javascript-typescript` |
| `Default setup configured` | `Configured languages` | only populated when default setup is actually configured |
| `Not configured (supported languages)` | `Languages not configured` | now populated |

**Gap counts will go up, and that is a fix rather than a regression in your
estate.** The original command reads the default setup language list without
checking whether default setup is on. For a repository with no code scanning
that list is an eligibility list, so it cancels out the detected languages and
the gap column comes back empty. `status` reports those gaps.

## Legacy command

The original language coverage audit is unchanged:

```bash
gh ghas-audit code-scanning --organization my-org --csv-output audit.csv
```

Use `code-scanning status` for scan health, freshness and per-language evidence.

## License

Licensed under the terms of the MIT open source license. See [MIT][license].

## Maintainers

- [@rvermeulen](https://github.com/rvermeulen) - Original Author
- [@theztefan](https://github.com/theztefan) - Core Maintainer

## Support

Please create [GitHub Issues][github-issues] for bugs or feature requests.

<!-- Resources -->

[license]: ./LICENSE.txt
[github-issues]: https://github.com/advanced-security/gh-ghas-audit/issues
[gh-cli]: https://cli.github.com/
