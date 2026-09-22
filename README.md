# gh-ghas-audit v2

A [GitHub CLI][gh-cli] extension for CodeQL configuration, execution, freshness and language coverage across repositories, organizations and enterprises.

## Installation

```bash
gh extension install advanced-security/gh-ghas-audit
```

## Quick start

```bash
gh ghas-audit code-scanning --organization my-org
gh ghas-audit code-scanning --enterprise my-enterprise
gh ghas-audit code-scanning -r owner/repo --scan-depth diagnostics
gh ghas-audit code-scanning -o my-org --status failing,stalled,stale,degraded --detailed
```

```text
HEALTH    REPOSITORY         CONFIG          EXECUTION    LAST SCAN   LANGUAGES
failing   my-org/payments    configured      failure      never       0/1 (not analyzed: java-kotlin)
stalled   my-org/checkout    configured      no-workflow  never       0/1 (not analyzed: go)
stale     my-org/legacy-api  configured      success      41 days ago 2/2
degraded  my-org/web         advanced-setup  success      today       1/1 (not configured: python)
healthy   my-org/identity    configured      success      today       3/3
```

For a per-language breakdown, use `--format language-csv`.

## Scan depth

One command and one collector. Every depth supports enterprise scope, filtering, caching, concurrency and all output formats.

| `--scan-depth` | Evidence | Use / limitation |
| --- | --- | --- |
| `config` | Inventory, default-setup languages and security-configuration attachment | Corrected legacy configuration audit. No runs, jobs, analyses, databases or logs. Never reports `healthy`; default setup off is `unknown` because advanced setup is not evaluated. |
| `health` **(default)** | Config plus workflows, runs, jobs, analyses and CodeQL databases | Default and advanced Actions workflow health. Does not see log-only quality warnings. |
| `diagnostics` | Health plus available latest-completed-run logs | Finds warnings behind successful workflows. Best effort and more expensive. |

Aliases: `low` = `config`, `med` / `medium` = `health`, `high` = `diagnostics`.

At diagnostics depth, `--deep-scope all` (default) includes apparently healthy repositories. `--deep-scope problematic` only inspects repositories already needing attention and therefore misses their healthy-looking counterparts' log-only warnings.

```bash
gh ghas-audit code-scanning -o my-org --scan-depth config
gh ghas-audit code-scanning -o my-org --scan-depth diagnostics --deep-scope problematic
```

## Scope and filters

| Flag | Purpose |
| --- | --- |
| `--organization`, `--organizations`, `-o` | One or more organizations, comma separated |
| `--enterprise`, `-e` | Discover every organization in an enterprise |
| `--repository`, `-r` | A single `OWNER/REPO`; cannot be combined with organization or enterprise scope |
| `--match`, `--exclude` | Include/exclude repository-name globs |
| `--visibility` | `public`, `private`, `internal` |
| `--skip-archived`, `--skip-forks` | Exclude archived repositories or forks |
| `--security-configuration` | Filter by a named security configuration |
| `--property-filter NAME=VALUE` | Filter by custom property; supports `*` wildcards |
| `--property NAME` | Include a property column |
| `--group-by-property NAME` | Group summary counts by a property |
| `--status` | Display only selected overall statuses |
| `--language` | Display repositories involving selected CodeQL languages |
| `--activity` | Display `active`, `inactive` or `unknown` repositories |

Scope filters run before per-repository collection. `--status`, `--language` and `--activity` are **display filters**: they do not reduce requests or log downloads.

Property names are case-insensitive. Multi-select properties match any value.
Property values containing literal commas cannot currently be filtered unambiguously.

```bash
gh ghas-audit code-scanning -o my-org --property-filter Project=WUPH --group-by-property Project
gh ghas-audit code-scanning -o my-org --match 'service-*' --exclude '*-sandbox'
```

## Status and language evidence

| Dimension | Values |
| --- | --- |
| `configuration` | `configured`, `not-configured`, `advanced-setup`, `external-ci`, `attaching`, `updating`, `attach-failed`, `unavailable`, `unknown` |
| `execution` | `success`, `failure`, `timed-out`, `cancelled`, `action-required`, `startup-failure`, `in-progress`, `queued`, `disabled`, `no-workflow`, `no-completed-run`, `not-applicable`, `not-evaluated`, `unknown` |
| `freshness` | `current`, `stale`, `never-scanned`, `not-applicable`, `not-evaluated`, `unknown` |
| `coverage` | `complete`, `partial`, `gap`, `no-supported-languages`, `not-applicable`, `unknown` |

| Overall status | Meaning |
| --- | --- |
| `failing` | The latest completed run failed |
| `stalled` | Missing/disabled workflow, no completed run, or failed configuration attachment |
| `stale` | No recent successful analysis |
| `degraded` | Missing/failed language coverage or a warning |
| `in-progress` | Scanning or configuration is in progress |
| `healthy` | Current, successful, fully covered at the selected depth |
| `not-configured` | Supported code exists but scanning is not configured |
| `not-applicable` | No supported code |
| `unavailable` | Configuration cannot be inspected, for example because Code Security is disabled |
| `unknown` | Insufficient evidence for a health verdict, including config-only assessments without a known problem |

`config` reports execution and freshness as `not-evaluated`. This is intentional, not a collection failure.

| Language field | Meaning |
| --- | --- |
| `detected_languages` | Supported source languages, normalized to CodeQL identifiers |
| `configured_languages` | Active default-setup selection, or inferred advanced analysis languages |
| `succeeded_languages` | Languages with successful analysis evidence |
| `missing_languages` | Detected supported languages not configured for scanning |
| `failed_languages` | Configured languages without successful evidence |
| `deselected_languages` | Languages run in the latest default-setup analysis but subsequently removed from configuration |
| `unsupported_languages` | Source languages CodeQL cannot analyze |

Kotlin normalizes to `java-kotlin`; JavaScript and TypeScript share `javascript-typescript`. A missing supported language is a coverage gap for both default and advanced setup, even when the omission was intentional. A completely unconfigured repository remains `not-configured`.

## Freshness

| Flag | Default | Purpose |
| --- | --- | --- |
| `--stale-after` | `8d` | Active repository scan age |
| `--stale-after-inactive` | `32d` | Inactive repository scan age |
| `--inactive-after` | `180d` | Time since the latest push or pull request update |

Durations accept days or Go duration syntax, such as `14d` or `36h`. Each row records its activity and applied threshold. Activity is an approximation; the organization's monthly-scanning setting is not exposed by the API.

## Output and exit codes

| Flag | Default / values |
| --- | --- |
| `--format` | `table` (default), `json`, `ndjson`, `csv`, `language-csv` |
| `--output PATH` | Write to a file instead of stdout |
| `--detailed` | Add explanations to the table |
| `--quiet` | Suppress progress on stderr |
| `--fail-on` | Comma-separated overall statuses that produce exit code `2` |

```bash
gh ghas-audit code-scanning -o my-org --scan-depth config --format csv --output configuration.csv
gh ghas-audit code-scanning -o my-org --format json --output report.json
gh ghas-audit code-scanning -o my-org --format language-csv --output languages.csv
gh ghas-audit code-scanning -o my-org --fail-on failing,stalled
```

| Format | Rows | Adds at diagnostics depth |
| --- | --- | --- |
| `json` | One report; canonical schema (`schema_version`, `settings.scan_depth`) | Full evidence, per language |
| `ndjson` | Report header, then one record per repository | Same fields as `json` |
| `csv` | One row per repository | `CodeQL version`, `Query packs`, `SARIF collected` (e.g. `6/6`), each rolled up across languages |
| `language-csv` | One row per repository/language | `Log CodeQL version`, per-language `SARIF collected`, query pack, rule count, results by level, artifact count, language mismatch |

`--no-sarif` leaves the SARIF-derived columns above blank rather than removing them; the CSV schema is unaffected. Both CSV formats add `Evidence complete`, plus a `Property: NAME` column per requested custom property.

Each language records `runtime_evaluation`: `not-evaluated`, `evaluated` or `incomplete`. Uncollected values are null in JSON/NDJSON, blank in language CSV.

| Exit | Meaning |
| --- | --- |
| `0` | Collection completed; no `--fail-on` match |
| `1` | Usage or command error |
| `2` | A collected repository matched `--fail-on`, even if display filters hide it |

**Exit `0` does not mean the report is complete.** Check `stats.incomplete`, repository `status.incomplete`, `errors` and report `warnings`. Unread evidence prevents `healthy`; known failures remain visible.

## Performance and diagnostics

| Flag | Default | Purpose |
| --- | --- | --- |
| `--concurrency` | `8` | Maximum concurrent API requests |
| `--cache-dir` | User cache directory | Persist ETags and response bodies |
| `--cache-max-age` | Unset | Ignore cache entries older than a duration |
| `--refresh` | Off | Clear the cache before collection |
| `--no-cache` | Off | Disable caching |
| `--deep-diagnostics-max-repos` | `200` | Maximum repositories inspected for logs and SARIF at diagnostics depth; `0` means unlimited |
| `--deep-diagnostics-max-mb` | `32` | Total compressed log download budget in MiB; `0` means unlimited |
| `--no-sarif` | Off | Disable SARIF download at diagnostics depth; log inspection is unaffected |
| `--deep-diagnostics-max-sarif-mb` | `1024` | Total SARIF download budget in MiB, independent of `--deep-diagnostics-max-mb`; `0` means unlimited |

### No-limits mode (compliance/exhaustive audits)

For a compliance audit where completeness must not be capped by a default budget, run diagnostics depth against every repository with every ceiling set to `0` (unlimited):

```sh
gh ghas-audit code-scanning -o my-org --scan-depth diagnostics --deep-scope all --deep-diagnostics-max-repos 0 --deep-diagnostics-max-mb 0 --deep-diagnostics-max-sarif-mb 0
```

This is the deepest evidence tier: `--deep-scope all` inspects every repository, and the three `0` values remove the repo-count, log-byte and SARIF-byte ceilings. Defaults exist to prevent an accidental unbounded run.

⚠️ **Before running unlimited on a large organization:**

- **Rate limit.** One log archive plus one SARIF per language per repository, on top of health depth's calls; hundreds of repositories can exhaust a 5,000/hour quota. Watch `stats.rate_limit_waits`; lower `--concurrency` if secondary limits trigger.
- **Disk and memory.** Logs/SARIF aren't written to the on-disk cache but sit in memory per repository (can reach hundreds of MiB). The metadata cache still grows with `--cache-dir`; pair with `--no-cache` if space is tight.
- **Runtime.** Log downloads are serialized, so expect minutes to hours, not seconds, on a large organization.
- **Start narrow.** Try `--match`, a small `--activity active` slice, or `--deep-scope problematic` first.

Inventory uses one GraphQL query per 50 repositories. Runtime evidence needs per-repository REST calls, paginated past 100 CodeQL analyses. ETag revalidation still makes network requests. Use scope filters and caching for large organizations.

REST throttling honors `Retry-After` and reset headers; recorded waits appear in `stats.rate_limit_waits`. Higher concurrency can trigger secondary limits.

Log downloads are serialized to share the byte budget; other collection stays concurrent. Missing, restricted, oversized or budget-skipped logs mark the repository incomplete, with the reason in `errors`.

| Log diagnostic | Effect |
| --- | --- |
| Error / warning | Failing or degraded, according to execution and coverage |
| Suggestion / information | No escalation |

Log findings carry `"source": "log"`. For example, low C# analysis quality or duplicate Java classes can make a successful workflow `degraded`; build-mode `none` suggestions do not.

### SARIF cross-check

At diagnostics depth, each default-branch language analysis's SARIF (`GET .../code-scanning/analyses/{id}` with `Accept: application/sarif+json`) is also downloaded unless `--no-sarif` is set. This adds, per language:

| Field | Meaning |
| --- | --- |
| `codeql_version`, `query_packs`, `rule_count` | From the SARIF tool driver and its extensions |
| `results_by_level` | Result count by SARIF severity level |
| `artifact_count` | Number of source artifacts SARIF recorded |
| `sarif_language` | Language CodeQL actually scanned, inferred from query pack/rule ID prefixes, independent of the analysis category |
| `sarif_language_mismatch` | Set when `sarif_language` disagrees with the category-derived language (informational only) |

Log parsing (deep diagnostics) also recovers `log_codeql_version` from the job log's toolcache path (e.g. `.../hostedtoolcache/CodeQL/2.27.0/x64`), independent of SARIF, so it covers a language whose SARIF fetch was skipped or failed. Query pack names are SARIF-only: logs only ever mention the top-level requested pack, never its dependencies.

Only structural SARIF fields are read; result messages, locations and source snippets are never parsed. SARIF has its own repository/byte budget (`--deep-diagnostics-max-sarif-mb`, default 1024 MiB) independent of the log budget, and bypasses the on-disk cache like logs do.

These fields appear in JSON, NDJSON and language CSV (plus `Log CodeQL version`). The table and repository CSV show aggregated `CodeQL version`/`Query packs` columns (version prefers SARIF, falls back to log-derived per language), tagged `value[language, ...]`, e.g. `2.20.3[java-kotlin, csharp]; 2.19.1[python]`. The table's `--detailed` mode and CSV's `SARIF collected` column share one `N/M collected` summary.

## Permissions and limitations

| Capability | Read permission |
| --- | --- |
| Repository inventory | Repository Metadata and Pull requests |
| Default setup, analyses, databases, SARIF | Repository Code scanning alerts |
| Runs, jobs, logs | Repository Actions |
| Security configurations and attachment | Organization Administration |
| Custom properties | Organization Custom properties |
| Enterprise discovery | Token scope `read:enterprise` |

GitHub App installation tokens work per organization, not for enterprise discovery. The workflow `GITHUB_TOKEN` cannot inventory an organization. An environment token overrides stored `gh auth` credentials.

- No exact tool-status-page parity: log format and retention limit diagnostics.
- Advanced workflow/language selection is inferred from observed analyses, not authoritative intended configuration. CodeQL from external CI is detected as `external-ci`, but its health and free-form category coverage are not evaluated. Third-party SARIF health is not evaluated.
- `actions` cannot be inferred from repository language statistics, so it is excluded from detected-language gaps.
- Config depth cannot distinguish advanced setup from default setup being off.
- Missing organization metadata is reported as a warning; explicit filters that cannot be evaluated fail that scope.

## Scheduled reporting

Install and invoke the CLI in a workflow. [`examples/code-scanning-status.yml`](examples/code-scanning-status.yml) uses App authentication, cache reuse, one collection, a job summary and artifact upload.

The App-token example is limited to runs under one hour. Split larger scopes or run long diagnostics directly with suitable longer-lived credentials.

## License and support

[MIT license](LICENSE.txt). Maintainers: [@rvermeulen](https://github.com/rvermeulen), [@theztefan](https://github.com/theztefan).

Report bugs and feature requests through [GitHub Issues][github-issues].

[github-issues]: https://github.com/advanced-security/gh-ghas-audit/issues
[gh-cli]: https://cli.github.com/
