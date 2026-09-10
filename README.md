# gh-ghas-audit GitHub CLI extension

`gh-ghas-audit` is a [GitHub CLI][gh-cli] extension that reports the health of
GitHub code scanning across organizations and enterprises.

Security teams can enable CodeQL default setup at scale, but once it is enabled
there is no organization-level view of whether scans are actually succeeding. A
repository can show as protected in the coverage view while its analysis
silently fails, never runs, stops running, or skips a language. Today the only
way to find those repositories is to open each one in turn.

This extension answers those questions from the command line, in a form you can
export, schedule, and hand to an auditor.

## Contents

- [What it reports](#what-it-reports)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Understanding the status dimensions](#understanding-the-status-dimensions)
- [Filtering and grouping](#filtering-and-grouping)
- [Output formats](#output-formats)
- [Scheduled reporting](#scheduled-reporting)
- [Permissions](#permissions)
- [Performance and rate limits](#performance-and-rate-limits)
- [Deep diagnostics](#deep-diagnostics)
- [Known limitations](#known-limitations)
- [Legacy command](#legacy-command)

## What it reports

For every repository in scope:

- Whether code scanning default setup is configured.
- Whether an organization or enterprise security configuration attached
  successfully, including rollouts that **failed to attach**.
- Whether the most recent analysis run succeeded, failed, timed out, is still
  running, or has **never completed at all**.
- **When the repository last scanned successfully**, and whether that is within
  your freshness threshold.
- **Which languages are actually being analyzed**, compared against the
  languages present in the repository and the languages default setup claims to
  cover.
- Languages present that CodeQL **cannot** analyze at all, such as Scala, so
  you know where CodeQL alone does not provide coverage.
- Direct links to the workflow run and the per-language job, as evidence.

## Installation

```bash
gh extension install advanced-security/gh-ghas-audit
```

To build from source:

```bash
git clone https://github.com/advanced-security/gh-ghas-audit.git
cd gh-ghas-audit
go build -o gh-ghas-audit .
gh extension install .
```

## Quick start

Report one organization:

```bash
gh ghas-audit code-scanning status --organization my-org
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

Report an entire enterprise:

```bash
gh ghas-audit code-scanning status --enterprise my-enterprise
```

Show only what needs attention, with an explanation for each row:

```bash
gh ghas-audit code-scanning status --organization my-org \
  --status failing,stalled,stale,degraded --detailed
```

## Understanding the status dimensions

A single pass or fail hides the problems that matter, so every repository is
reported across four independent dimensions.

| Dimension | Values | Question it answers |
| --- | --- | --- |
| `configuration` | `configured`, `not-configured`, `attaching`, `updating`, `attach-failed`, `unavailable` | Is code scanning set up, and did the security configuration attach? |
| `execution` | `success`, `failure`, `timed-out`, `cancelled`, `action-required`, `startup-failure`, `in-progress`, `queued`, `no-workflow`, `no-completed-run` | Did the most recent analysis run succeed, fail, or never run? |
| `freshness` | `current`, `stale`, `never-scanned` | How long ago did this repository last scan successfully, against the threshold for its scan schedule? |
| `coverage` | `complete`, `partial`, `gap`, `no-supported-languages` | Are all supported languages actually being analyzed? |

Those four roll up into one `overall` severity, used for sorting and summary
counts, with a fixed precedence:

| Severity | Meaning |
| --- | --- |
| `failing` | The most recent analysis run failed, timed out, or was cancelled. |
| `stalled` | Scanning is configured but is not running: no managed workflow, no completed run, or the security configuration failed to attach. |
| `stale` | Scanning succeeded, but not within the freshness threshold. |
| `degraded` | Scanning succeeded, but a language is not analyzed, a language is not configured, or a warning was found. |
| `in-progress` | A run is currently executing, or a configuration is still attaching. |
| `healthy` | Configured, current, and fully covered. |
| `not-configured` | Code scanning is not enabled, and the repository contains code CodeQL could analyze. |
| `not-applicable` | Nothing in the repository can be analyzed by CodeQL. |
| `unavailable` | The repository could not be inspected, usually because code security is not enabled for it. |

Two distinctions are deliberate and matter in practice:

- **`stalled` is not `failing`.** A repository whose default setup is
  configured but which has never produced a completed run looks protected in
  coverage views and green in Actions, because there is nothing to be red. It
  is reported separately because it is otherwise invisible.
- **`not-applicable` is not `not-configured`.** An empty repository, or one
  containing only HTML and CSS, keeps default setup "configured" forever.
  Reporting those as broken would bury the genuine failures.

## Filtering and grouping

Scope:

| Flag | Purpose |
| --- | --- |
| `--organization`, `-o` | One or more organizations, comma separated. |
| `--enterprise`, `-e` | Every organization in an enterprise. |
| `--repository`, `-r` | A single `OWNER/REPO`. |

Narrowing:

| Flag | Purpose |
| --- | --- |
| `--status` | Only report these overall statuses. |
| `--language` | Only report repositories involving these CodeQL languages. |
| `--visibility` | Only scan `public`, `private` or `internal` repositories. |
| `--match`, `--exclude` | Glob patterns on repository name, for example `--match 'team-*'`. |
| `--skip-archived`, `--skip-forks` | Exclude archived or forked repositories. |
| `--security-configuration` | Only repositories attached to a named security configuration. |
| `--property-filter` | Only repositories whose custom property matches, as `NAME=VALUE`. |
| `--activity` | Only `active` or `inactive` repositories. |
| `--stale-after` | Freshness threshold for active repositories, default `8d`. |
| `--stale-after-inactive` | Freshness threshold for inactive repositories, default `32d`. Use `off` to skip. |
| `--inactive-after` | Time without a push that makes a repository inactive, default `180d`. |

`--match`, `--exclude`, `--visibility` and `--property-filter` are applied
before any per-repository request, so excluded repositories cost nothing.

### Freshness thresholds and repository activity

GitHub scans default setup repositories weekly, **except** repositories with no
pushes or pull requests for six months or more. When an organization enables
*Keep scheduled scans running every 30 days for inactive repositories*, those
are scanned monthly instead
([changelog](https://github.blog/changelog/2026-06-09-periodic-code-scanning-of-inactive-repositories/)).

Holding a monthly-scanned repository to a weekly threshold would report it as
stale for 23 days out of every 30, so two thresholds are applied:

| Flag | Default | Applies to |
| --- | --- | --- |
| `--stale-after` | `8d` | Active repositories (weekly schedule plus a day of tolerance) |
| `--stale-after-inactive` | `32d` | Inactive repositories (monthly schedule plus tolerance) |
| `--inactive-after` | `180d` | Time without a push after which a repository counts as inactive |

Each repository reports which threshold was applied, so a stale verdict always
explains itself:

```text
HEALTH  REPOSITORY   LAST SCAN               DETAIL
stale   org/Infinity 204 days ago (inactive) no successful analysis within 32d (inactive); this
                                             repository has had no recent pushes, so GitHub scans
                                             it monthly at most
stale   org/Web      20 days ago             no successful analysis within 8d
```

Filter to one population with `--activity`:

```bash
# Actively developed repositories that are not being scanned. Usually the
# most urgent, because the code is changing.
gh ghas-audit code-scanning status -o my-org --activity active --status stale,failing,stalled

# Dormant repositories that have fallen out of the monthly cycle.
gh ghas-audit code-scanning status -o my-org --activity inactive --status stale
```

If your organization has **not** enabled monthly scanning of inactive
repositories, those repositories stop being scanned altogether and would be
reported stale indefinitely. Turn the check off for them:

```bash
gh ghas-audit code-scanning status -o my-org --stale-after-inactive off
```

Use `--inactive-after off` to disable the distinction entirely and hold every
repository to `--stale-after`.

Two caveats worth knowing. Activity is inferred from the repository push
timestamp, which is the closest public signal to GitHub's own "no pushes or
pull requests" rule; they agree in practice, because opening a pull request
requires pushing a branch, but this is an approximation. And the organization
setting itself is not exposed by any API, so the tool cannot detect whether
monthly scanning is switched on: `--stale-after-inactive` is how you tell it.

### Grouping by application

Most organizations map repositories to applications using custom properties.
`--group-by-property` aggregates the summary by that property, turning a
repository list into an application-level view:

```bash
gh ghas-audit code-scanning status --organization my-org \
  --group-by-property application
```

```text
By application
  payments-platform                18 repositories, 4 needing attention
  identity                          9 repositories, 0 needing attention
  (not set)                        11 repositories, 2 needing attention
```

Repositories with no value are grouped under `(not set)`, which also shows how
complete your property data is.

Property names are matched case-insensitively, so `--group-by-property project`
finds a property the organization defined as `Project`. Multi-select properties
match on any one of their values, so `--property-filter Project=Internal`
selects a repository whose `Project` is `INFINITY, Internal`.

### Freshness threshold

See [Freshness thresholds and repository activity](#freshness-thresholds-and-repository-activity)
above. In short, active repositories are held to `--stale-after` (default
`8d`) and inactive ones to `--stale-after-inactive` (default `32d`):

```bash
gh ghas-audit code-scanning status --organization my-org --stale-after 14d
```

## Output formats

| Format | Use |
| --- | --- |
| `table` | Terminal review. Add `--detailed` for an explanation column. |
| `json` | The complete, versioned report. This is the canonical data contract. |
| `ndjson` | One header record plus one record per repository, for very large estates and streaming pipelines. |
| `csv` | One row per repository. |
| `language-csv` | One row per repository language, for per-language coverage questions. |

```bash
gh ghas-audit code-scanning status -o my-org --format csv --output status.csv
gh ghas-audit code-scanning status -o my-org --format language-csv --output languages.csv
gh ghas-audit code-scanning status -o my-org --format json --output status.json
```

The JSON document carries `schema_version`, the scope and settings used, the
summary, per-repository status and evidence, collection warnings, and request
statistics. Check `schema_version` before parsing, and check `stats.incomplete`
before treating the report as authoritative:

```bash
jq -r '.repositories[] | select(.status.overall == "stalled") | .full_name' status.json
jq '.summary.by_severity' status.json
jq '.stats.incomplete' status.json
```

### Exit codes for automation

| Code | Meaning |
| --- | --- |
| `0` | The scan completed and nothing matched `--fail-on`. |
| `1` | The tool failed. |
| `2` | The scan completed and `--fail-on` matched. |

```bash
gh ghas-audit code-scanning status -o my-org --fail-on failing,stalled
```

## Scheduled reporting

The extension is not packaged as a GitHub Action. Peer extensions in this
organization are not either, and wrapping a CLI in an Action would create a
second implementation and a second data contract to keep in step. Instead,
install the released extension in a workflow and invoke it.

A complete scheduled workflow, including GitHub App authentication, cache
reuse, a job summary and artifact upload, is in
[`examples/code-scanning-status.yml`](examples/code-scanning-status.yml).

## Permissions

The token must be able to read every repository you want reported. Missing
permissions produce `unavailable` rows rather than silent omissions, and set
`stats.incomplete`.

| Capability | Requirement |
| --- | --- |
| Repository inventory and languages | Repository `Metadata: read` |
| Default setup and CodeQL databases | Repository `Code scanning alerts: read` |
| Workflow runs and jobs | Repository `Actions: read` |
| Security configurations and attachment status | Organization `Administration: read` |
| Custom properties | Organization `Custom properties: read` |
| `--enterprise` discovery | A token with the `read:enterprise` scope |

`--enterprise` uses GraphQL, which needs an enterprise-scoped token. GitHub App
installation tokens are scoped to a single organization and cannot list an
enterprise, so either run once per organization or use a scoped personal access
token. If the scope is missing, the tool says so and suggests
`gh auth refresh -h github.com -s read:enterprise`.

The Actions `GITHUB_TOKEN` is scoped to its own repository and cannot inventory
an organization.

## Performance and rate limits

A configured repository costs roughly five REST requests: default setup,
workflow list, workflow runs, run jobs, and CodeQL databases. Repository
inventory and languages come from GraphQL, one query per 50 repositories, which
avoids a per-repository languages request.

Repositories that are not configured cost one request, and repositories
excluded by a filter cost nothing.

Measured against a real eight-organization enterprise of 35 repositories:

| Run | REST requests | 304 cache hits | Rate limit consumed |
| --- | --- | --- | --- |
| Cold | 145 | 0 | 145 |
| Warm, same cache | 145 | 137 | 9 |

Conditional requests are the main scaling lever. GitHub does not count `304 Not
Modified` responses against the primary rate limit, so a repeated scan of an
unchanged estate costs almost nothing in quota. Note that a warm run is not
much faster in wall clock time, because each request is still a round trip; the
saving is quota, which is what constrains large estates.

Cached responses are written straight to disk rather than held in memory, so
memory use stays flat regardless of how many repositories are scanned. Use
`--cache-max-age` to have old entries pruned automatically.

Guidance for large estates:

- Use a **GitHub App installation token**. It receives a higher primary rate
  limit than a personal access token, and each organization installation has
  its own budget.
- Keep `--concurrency` moderate. The default of 8 is deliberately well below
  GitHub's concurrency ceiling; raising it increases the risk of secondary rate
  limits, which cost more time than they save.
- Use `--cache-dir` on every run, and `--refresh` only when you deliberately
  want to discard cached responses.
- Narrow with `--match`, `--exclude` or `--property-filter` when you only care
  about part of the estate.

Primary and secondary rate limits are handled automatically: the tool honours
`Retry-After` and rate limit reset headers and backs off with jitter. Waits are
reported in `stats.rate_limit_waits`.

## Deep diagnostics

`--deep-diagnostics` downloads and parses Actions logs to recover warning text
that no API exposes, such as dependency extraction failures or an unreachable
package registry.

```bash
# Only inspect repositories that already look unhealthy.
gh ghas-audit code-scanning status -o my-org --deep-diagnostics problematic

# Also inspect healthy repositories. This is the only mode that can find a
# warning hidden behind a completely green workflow run.
gh ghas-audit code-scanning status -o my-org --deep-diagnostics all
```

Understand the trade-offs before enabling it:

- **It is slow and rate limit heavy.** Each inspected repository downloads a
  full log archive, far larger than any API response. Use a GitHub App
  installation token rather than a personal access token.
- **It is best effort.** Log text is unstructured and can change without
  notice. Findings are labelled `"source": "log"` in the output and are never
  presented as authoritative tool status.
- **It is bounded.** `--deep-diagnostics-max-repos` (default 200) and
  `--deep-diagnostics-max-mb` (default 32) cap the work. When a limit is
  reached, inspection stops rather than running unbounded.

Only genuine Actions annotations are considered. Analysis logs contain large
configuration dumps and query traces that mention words such as "warning",
"dependency" and "analysis quality" during entirely healthy runs, so scanning
raw log text produces false positives. Recognized problems get a stable code;
anything unrecognized is reported verbatim rather than guessed at. Routine
noise, such as action and Node.js deprecation notices, is filtered out.

## Known limitations

These are limits of the public GitHub API, not of this tool. They are stated
plainly so the report is not mistaken for something it cannot be.

- **No exact parity with the repository tool status page.** GitHub does not
  expose that page's warnings through REST or GraphQL. This tool reconstructs
  health from configuration, run, job and CodeQL database evidence, and can
  optionally recover warning text from logs, but the two will not always agree.
- **Coverage is inferred, not declared.** Whether a language was analyzed is
  derived from per-language jobs and CodeQL databases. A language configured in
  default setup with no successful analysis is reported as not analyzed.
- **`actions` cannot be detected from source.** It is never reported as an
  unconfigured coverage gap, because there is no reliable way to verify it.
- **Advanced setup and third-party SARIF are not evaluated yet.** Only default
  setup scan health is reported. Repositories using an advanced setup workflow
  are reported by their configuration state rather than their scan health.
- **Enterprise scans need an enterprise-scoped token.** See
  [Permissions](#permissions).
- **There is no push notification.** GitHub has no code scanning specific
  webhook for analysis degradation, so this is a pull-based report. Schedule it
  rather than expecting an alert.
- **A partial scan is marked, not hidden.** If any evidence could not be read,
  that repository is never reported as `healthy`: its status carries
  `incomplete`, the CSV `Evidence complete` column is `false`, and the reason
  is recorded. At report level, `stats.incomplete` is `true` and warnings are
  included. Absence of a problem in an incomplete report does not prove absence
  of a problem.
- **Rate limits are never reported as repository health.** A throttled request
  is retried, and if the retry budget is exhausted it is recorded as a
  collection error rather than as the repository being unreadable.

## Legacy command

The original language coverage audit is unchanged:

```bash
gh ghas-audit code-scanning --organization my-org --csv-output audit.csv
```

It reports detected languages against configured default setup languages. Use
`code-scanning status` for scan health, freshness and per-language evidence.

## License

This project is licensed under the terms of the MIT open source license. Please
refer to [MIT][license] for the full terms.

## Maintainers

- [@rvermeulen](https://github.com/rvermeulen) - Original Author
- [@theztefan](https://github.com/theztefan) - Core Maintainer

## Support

Please create [GitHub Issues][github-issues] if there are bugs or feature
requests.

<!-- Resources -->

[license]: ./LICENSE.txt
[github-issues]: https://github.com/advanced-security/gh-ghas-audit/issues
[gh-cli]: https://cli.github.com/
