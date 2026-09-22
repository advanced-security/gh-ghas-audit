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

The table above is one row per repository. For a per-language breakdown (one row per repository/language pair), use `--format language-csv` instead; see [Output and exit codes](#output-and-exit-codes).

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

Repository CSV includes the four dimensions, language lists, run links, configuration, diagnostics, reasons and errors, plus (at diagnostics depth) a `CodeQL version` and (unless `--no-sarif`) `Query packs` and `SARIF collected` columns aggregated across the repository's languages; `CodeQL version` prefers SARIF but falls back to the log-derived version for a language SARIF could not cover, and `SARIF collected` is a `collected/attempted` count (for example `6/6`) with any language-mismatch or SARIF-error languages called out, left blank when SARIF was never attempted for that repository. Language CSV includes per-language analysis evidence, errors, and (at diagnostics depth) a `Log CodeQL version` column plus (unless `--no-sarif`) a per-language `SARIF collected` boolean, SARIF-derived query pack, rule count, results-by-level, artifact count and language cross-check fields. Both include `Evidence complete`; custom properties add `Property: NAME` columns.

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
| `--deep-diagnostics-max-repos` | `200` | Maximum repositories inspected for logs and SARIF at diagnostics depth; `0` means unlimited |
| `--deep-diagnostics-max-mb` | `32` | Total compressed log download budget in MiB; `0` means unlimited |
| `--no-sarif` | Off | Disable SARIF download at diagnostics depth; log inspection is unaffected |
| `--deep-diagnostics-max-sarif-mb` | `1024` | Total SARIF download budget in MiB, independent of `--deep-diagnostics-max-mb`; `0` means unlimited |

### No-limits mode (compliance/exhaustive audits)

For a compliance audit where completeness must not be capped by a default budget, run diagnostics depth against every repository with every ceiling set to `0` (unlimited):

```sh
gh ghas-audit code-scanning -o my-org --scan-depth diagnostics --deep-scope all --deep-diagnostics-max-repos 0 --deep-diagnostics-max-mb 0 --deep-diagnostics-max-sarif-mb 0
```

This is the deepest evidence tier the tool can produce: `--deep-scope all` inspects every repository, not just those already flagged as needing attention, and the three `0` budgets remove the repository-count, log-byte and SARIF-byte ceilings that would otherwise stop collection early on a large organization. Use this as the reference command for a full compliance sweep; the defaults above exist specifically to keep an accidental unbounded run from happening.

⚠️ **Before running unlimited on a large organization:**

- **Rate limit.** Every repository at diagnostics depth downloads a full Actions log archive and one SARIF file per language analysis, on top of the REST calls health depth already makes. An organization of hundreds of repositories can exhaust a 5,000/hour REST quota in one run; watch `stats.rate_limit_waits` (throttling already honors `Retry-After` and reset headers) and consider a lower `--concurrency` if secondary limits start triggering.
- **Disk and memory.** Log and SARIF downloads are never persisted to the on-disk cache (only their parsed findings are), but they are held in memory for the duration of each repository's inspection, and a single repository's combined archives can run into hundreds of MiB with real `0` limits. The metadata cache (ETags, response bodies for everything *other* than logs/SARIF) still grows with `--cache-dir`; for a very large organization, confirm the cache volume has room, or pair unlimited mode with `--no-cache` to avoid growing it further.
- **Runtime.** Log downloads are serialized to share one byte budget, so this mode is considerably slower than health depth; expect a full-organization run to take minutes to hours rather than seconds, depending on repository count and log/SARIF sizes.
- **Start narrow first.** Validate the command against `--match` or a small `--activity active` slice, or with `--deep-scope problematic`, before removing every limit across an entire organization.

Inventory uses one GraphQL query per 50 repositories. Runtime evidence requires per-repository REST calls; repositories with more than 100 CodeQL analysis records require additional paginated requests. ETag revalidation saves primary quota but still makes network requests. Large organizations are batch workloads: use scope filters, caching and suitable API quotas.

REST throttling honours `Retry-After` and reset headers. Recorded waits appear in `stats.rate_limit_waits`. Increasing concurrency can trigger secondary limits.

Log downloads are serialized to enforce the shared byte budget; other collection remains concurrent. Missing, restricted, oversized or budget-skipped logs mark the affected repository and report incomplete, with the reason recorded in `errors`.

| Log diagnostic | Effect |
| --- | --- |
| Error / warning | Failing or degraded, according to execution and coverage |
| Suggestion / information | No escalation |

Log findings carry `"source": "log"`. For example, low C# analysis quality or duplicate Java classes can make a successful workflow `degraded`; build-mode `none` suggestions do not.

### SARIF cross-check

At diagnostics depth, each default-branch language analysis's SARIF representation (`GET .../code-scanning/analyses/{id}` with `Accept: application/sarif+json`, the same endpoint and permission already used for its metadata) is also downloaded unless `--no-sarif` is set. This adds, per language:

- `codeql_version`, `query_packs` and `rule_count`, read from the SARIF tool driver and its extensions.
- `results_by_level`, a count of results by SARIF severity level.
- `artifact_count`, the number of source artifacts SARIF recorded.
- `sarif_language`, the language CodeQL actually scanned, inferred from query pack names and rule ID prefixes, independent of the analysis category string. This matters for custom or API-based CodeQL uploads, which are not guaranteed to use the same category names a default or advanced-setup workflow would.
- `sarif_language_mismatch`, set when `sarif_language` disagrees with the analysis's own category-derived language. This is informational: a mismatch alone does not change a repository's overall status.

Deep diagnostics (Actions log parsing) also recovers `log_codeql_version`, the CodeQL CLI version read from the job log's toolcache path (for example `.../hostedtoolcache/CodeQL/2.27.0/x64`). It is independent of SARIF and of `--no-sarif`: it comes from `--scan-depth diagnostics` log inspection, so it remains available for a language whose SARIF fetch was skipped or failed, such as one with a known analysis error. When a log shows an old CodeQL version deleted mid-run and a newer one installed afterwards, the later version is kept as the one actually used for analysis. Query pack names are not recovered from logs: real-world log samples only ever mention the top-level requested pack, never its extension or dependency packs, so a log-derived pack list would be silently incomplete.

Only structural SARIF fields are read. Result messages, locations and source snippets are never parsed or retained. SARIF downloads share the `--deep-scope` selection with log inspection but have their own repository and byte budgets (`--deep-diagnostics-max-sarif-mb`, defaulting to 1024 MiB), so a large SARIF response cannot exhaust the log budget or vice versa. Like logs, SARIF bodies bypass the on-disk cache and are never persisted beyond the fields above.

These fields appear in JSON, NDJSON and language CSV (which also has a `Log CodeQL version` column). The terminal table and repository CSV also show a `CODEQL VERSION`/`CodeQL version` and `QUERY PACKS`/`Query packs` column, each aggregated across every language in the repository; the version column prefers SARIF's `codeql_version` but falls back to `log_codeql_version` for a language SARIF could not cover. Languages that share the same CodeQL version are grouped together; every entry is tagged `value[language, ...]` so multi-language repositories never leave it ambiguous which language a version or pack belongs to, for example `2.20.3[java-kotlin, csharp]; 2.19.1[python]`. The table's `--detailed` mode and the repository CSV's `SARIF collected` column both show the same per-repository `N/M collected` note, alongside any mismatch or SARIF-error languages.

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
