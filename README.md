# gh-ghas-audit v2

A [GitHub CLI][gh-cli] extension for CodeQL configuration, execution, freshness and language coverage across repositories, organizations and enterprises.

## Installation

```bash
gh extension install advanced-security/gh-ghas-audit
```

These instructions describe **v2**. Until v2 is released, build this branch with Go 1.23 or later. See [Upgrading from 1.x](#upgrading-from-1x) for breaking changes.

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

JSON is the canonical report. `schema_version` versions the data contract independently of the CLI release; `settings.scan_depth` records the evidence tier. NDJSON emits a report header followed by repository records after collection completes.

Repository CSV includes the four dimensions, language lists, run links, configuration, diagnostics, reasons and errors. Language CSV includes per-language analysis evidence and errors. Both include `Evidence complete`; custom properties add `Property: NAME` columns.

Each language records `runtime_evaluation`: `not-evaluated`, `evaluated` or `incomplete`. Uncollected `analyzed`/`succeeded` values are null in JSON/NDJSON and blank in language CSV.

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
| `--deep-diagnostics-max-repos` | `200` | Maximum repositories inspected for logs |
| `--deep-diagnostics-max-mb` | `32` | Total compressed log download budget in MiB |

Inventory uses one GraphQL query per 50 repositories. Runtime evidence requires per-repository REST calls; repositories with more than 100 CodeQL analysis records require additional paginated requests. ETag revalidation saves primary quota but still makes network requests. Large organizations are batch workloads: use scope filters, caching and suitable API quotas.

REST throttling honours `Retry-After` and reset headers. Recorded waits appear in `stats.rate_limit_waits`. Increasing concurrency can trigger secondary limits.

Log downloads are serialized to enforce the shared byte budget; other collection remains concurrent. Missing, restricted, oversized or budget-skipped logs mark the affected repository and report incomplete, with the reason recorded in `errors`.

| Log diagnostic | Effect |
| --- | --- |
| Error / warning | Failing or degraded, according to execution and coverage |
| Suggestion / information | No escalation |

Log findings carry `"source": "log"`. For example, low C# analysis quality or duplicate Java classes can make a successful workflow `degraded`; build-mode `none` suggestions do not.

## Permissions and limitations

| Capability | Read permission |
| --- | --- |
| Repository inventory | Repository Metadata and Pull requests |
| Default setup, analyses, databases | Repository Code scanning alerts |
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

## Upgrading from 1.x

**V2 replaces the legacy implementation.** There is no `status` subcommand or compatibility implementation.

| Previous invocation / behavior | V2 |
| --- | --- |
| `code-scanning -o ORG` ran a configuration audit | Defaults to `--scan-depth health` |
| Configuration-only audit | Add `--scan-depth config`; all modern formats, filters, caching and enterprise scope remain available |
| `code-scanning status ...` from development builds | Remove `status` |
| `--csv-output audit.csv` | Use `--format csv --output audit.csv` |
| Six-column legacy CSV | Expanded schema at every depth; parse headers, not positions |

```bash
gh ghas-audit code-scanning -o my-org --scan-depth config --format csv --output audit.csv
```

| 1.x CSV column | V2 column / change |
| --- | --- |
| `Organization`, `Repository` | Same names |
| `Default setup enabled?` | `Configuration status`: `Enabled`/`Disabled`/`Unknown` become status enums |
| `Languages in repo` | `Detected languages`, with aliases normalized |
| `Default setup configured` | `Configured languages`, populated only from active configuration or advanced evidence |
| `Not configured (supported languages)` | `Languages not configured`, including entirely unconfigured repositories |

Depth selects evidence, **not the old CSV schema or old bugs**. Corrected state checks and language normalization can change gap counts without repository changes.

## License and support

[MIT license](LICENSE.txt). Maintainers: [@rvermeulen](https://github.com/rvermeulen), [@theztefan](https://github.com/theztefan).

Report bugs and feature requests through [GitHub Issues][github-issues].

[github-issues]: https://github.com/advanced-security/gh-ghas-audit/issues
[gh-cli]: https://cli.github.com/
