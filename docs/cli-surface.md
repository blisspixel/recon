# CLI Surface

Generated from the live Typer command tree by `scripts/generate_surface_inventory.py`.
Do not edit by hand.

This is a derived maintainer and agent-author reference, not a stable runtime API contract.

## Command Index

- [`recon`](#recon)
- [`recon batch`](#recon-batch)
- [`recon cache`](#recon-cache)
- [`recon delta`](#recon-delta)
- [`recon discover`](#recon-discover)
- [`recon doctor`](#recon-doctor)
- [`recon fingerprints`](#recon-fingerprints)
- [`recon lookup`](#recon-lookup)
- [`recon mcp`](#recon-mcp)
- [`recon signals`](#recon-signals)
- [`recon update`](#recon-update)
- [`recon cache clear`](#recon-cache-clear)
- [`recon cache show`](#recon-cache-show)
- [`recon fingerprints check`](#recon-fingerprints-check)
- [`recon fingerprints list`](#recon-fingerprints-list)
- [`recon fingerprints new`](#recon-fingerprints-new)
- [`recon fingerprints search`](#recon-fingerprints-search)
- [`recon fingerprints show`](#recon-fingerprints-show)
- [`recon fingerprints test`](#recon-fingerprints-test)
- [`recon mcp doctor`](#recon-mcp-doctor)
- [`recon mcp install`](#recon-mcp-install)
- [`recon signals list`](#recon-signals-list)
- [`recon signals search`](#recon-signals-search)
- [`recon signals show`](#recon-signals-show)

<a id="recon"></a>
## `recon`

Kind: group
Summary: Domain intelligence from the command line.
Children: `batch`, `cache`, `delta`, `discover`, `doctor`, `fingerprints`, `lookup`, `mcp`, `signals`, `update`

| Name | Kind | Tokens | Required | Type | Default | Choices |
|---|---|---|---|---|---|---|
| `version` | option | `-V`, `--version` | no | boolean |  |  |
| `debug` | option | `--debug` | no | boolean | false |  |
| `color` | option | `--color`, `--no-color` | no | boolean |  |  |
| `install_completion` | option | `--install-completion` | no | boolean |  |  |
| `show_completion` | option | `--show-completion` | no | boolean |  |  |

<a id="recon-batch"></a>
## `recon batch`

Kind: command
Summary: Look up multiple domains from a file.

| Name | Kind | Tokens | Required | Type | Default | Choices |
|---|---|---|---|---|---|---|
| `file` | argument | `file` | yes | text |  |  |
| `json_output` | option | `--json` | no | boolean | false |  |
| `markdown` | option | `--md` | no | boolean | false |  |
| `csv_output` | option | `--csv` | no | boolean | false |  |
| `concurrency` | option | `--concurrency`, `-c` | no | integer | 5 |  |
| `include_unclassified` | option | `--include-unclassified` | no | boolean | false |  |
| `no_ct` | option | `--no-ct` | no | boolean | false |  |
| `ndjson` | option | `--ndjson` | no | boolean | false |  |
| `include_ecosystem` | option | `--include-ecosystem` | no | boolean | false |  |
| `fusion` | option | `--fusion`, `--no-fusion` | no | boolean | true |  |
| `summary` | option | `--summary` | no | boolean | false |  |

<a id="recon-cache"></a>
## `recon cache`

Kind: group
Summary: Manage the CT subdomain cache and TenantInfo result cache.
Children: `clear`, `show`

No parameters.

<a id="recon-delta"></a>
## `recon delta`

Kind: command
Summary: Compare the current lookup against the last cached TenantInfo.

| Name | Kind | Tokens | Required | Type | Default | Choices |
|---|---|---|---|---|---|---|
| `domain` | argument | `domain` | yes | text |  |  |
| `json_output` | option | `--json` | no | boolean | false |  |
| `timeout` | option | `--timeout` | no | float | 120.0 |  |

<a id="recon-discover"></a>
## `recon discover`

Kind: command
Summary: Mine a single domain for fingerprint candidates in one shot.

| Name | Kind | Tokens | Required | Type | Default | Choices |
|---|---|---|---|---|---|---|
| `domain` | argument | `domain` | yes | text |  |  |
| `output` | option | `--output`, `-o` | no | text |  |  |
| `no_ct` | option | `--no-ct` | no | boolean | false |  |
| `timeout` | option | `--timeout`, `-t` | no | float | 120.0 |  |
| `keep_intra_org` | option | `--keep-intra-org` | no | boolean | false |  |
| `min_count` | option | `--min-count` | no | integer | 1 |  |

<a id="recon-doctor"></a>
## `recon doctor`

Kind: command
Summary: Check connectivity to all data sources.

| Name | Kind | Tokens | Required | Type | Default | Choices |
|---|---|---|---|---|---|---|
| `fix` | option | `--fix` | no | boolean | false |  |
| `mcp` | option | `--mcp` | no | boolean | false |  |
| `client` | option | `--client` | no | text |  |  |

<a id="recon-fingerprints"></a>
## `recon fingerprints`

Kind: group
Summary: Inspect the built-in fingerprint catalog.
Children: `check`, `list`, `new`, `search`, `show`, `test`

No parameters.

<a id="recon-lookup"></a>
## `recon lookup`

Kind: command
Summary: Look up a domain. This is the default command.

| Name | Kind | Tokens | Required | Type | Default | Choices |
|---|---|---|---|---|---|---|
| `domain` | argument | `domain` | yes | text |  |  |
| `json_output` | option | `--json` | no | boolean | false |  |
| `markdown` | option | `--md` | no | boolean | false |  |
| `plain` | option | `--plain` | no | boolean | false |  |
| `services` | option | `--services`, `-s` | no | boolean | false |  |
| `domains` | option | `--domains`, `-d` | no | boolean | false |  |
| `full` | option | `--full`, `-f` | no | boolean | false |  |
| `verbose` | option | `--verbose`, `-v` | no | boolean | false |  |
| `sources` | option | `--sources` | no | boolean | false |  |
| `timeout` | option | `--timeout`, `-t` | no | float | 120.0 |  |
| `posture` | option | `--posture`, `-p` | no | boolean | false |  |
| `compare` | option | `--compare` | no | text |  |  |
| `chain` | option | `--chain` | no | boolean | false |  |
| `depth` | option | `--depth` | no | integer | 1 |  |
| `no_cache` | option | `--no-cache` | no | boolean | false |  |
| `cache_ttl` | option | `--cache-ttl` | no | integer | 86400 |  |
| `exposure` | option | `--exposure` | no | boolean | false |  |
| `gaps` | option | `--gaps` | no | boolean | false |  |
| `explain` | option | `--explain` | no | boolean | false |  |
| `profile` | option | `--profile` | no | text |  |  |
| `confidence_mode` | option | `--confidence-mode` | no | text | hedged |  |
| `fusion` | option | `--fusion`, `--no-fusion` | no | boolean | true |  |
| `explain_dag` | option | `--explain-dag` | no | boolean | false |  |
| `explain_dag_format` | option | `--explain-dag-format` | no | text | text |  |
| `include_unclassified` | option | `--include-unclassified` | no | boolean | false |  |
| `no_ct` | option | `--no-ct` | no | boolean | false |  |
| `direct_probes` | option | `--direct-probes` | no | boolean | false |  |
| `exact` | option | `--exact` | no | boolean | false |  |

<a id="recon-mcp"></a>
## `recon mcp`

Kind: group
Summary: MCP server commands: start the stdio server, install client config, run a self-check.
Children: `doctor`, `install`

No parameters.

<a id="recon-signals"></a>
## `recon signals`

Kind: group
Summary: Inspect the built-in signal catalog.
Children: `list`, `search`, `show`

No parameters.

<a id="recon-update"></a>
## `recon update`

Kind: command
Summary: Check for and install the latest recon release.

| Name | Kind | Tokens | Required | Type | Default | Choices |
|---|---|---|---|---|---|---|
| `check` | option | `--check` | no | boolean | false |  |

<a id="recon-cache-clear"></a>
## `recon cache clear`

Kind: command
Summary: Clear both CT subdomain cache and TenantInfo result cache.

| Name | Kind | Tokens | Required | Type | Default | Choices |
|---|---|---|---|---|---|---|
| `domain` | argument | `domain` | no | text |  |  |
| `all_domains` | option | `--all` | no | boolean | false |  |
| `force` | option | `--force`, `-f` | no | boolean | false |  |

<a id="recon-cache-show"></a>
## `recon cache show`

Kind: command
Summary: Show CT cache state for a domain, or list all cached domains.

| Name | Kind | Tokens | Required | Type | Default | Choices |
|---|---|---|---|---|---|---|
| `domain` | argument | `domain` | no | text |  |  |

<a id="recon-fingerprints-check"></a>
## `recon fingerprints check`

Kind: command
Summary: Validate fingerprint YAML files and flag duplicate slugs.

| Name | Kind | Tokens | Required | Type | Default | Choices |
|---|---|---|---|---|---|---|
| `path` | argument | `path` | no | text |  |  |
| `quiet` | option | `--quiet`, `-q` | no | boolean | false |  |

<a id="recon-fingerprints-list"></a>
## `recon fingerprints list`

Kind: command
Summary: List built-in fingerprints.

| Name | Kind | Tokens | Required | Type | Default | Choices |
|---|---|---|---|---|---|---|
| `category` | option | `--category`, `-c` | no | text |  |  |
| `detection_type` | option | `--type`, `-t` | no | text |  |  |
| `all_entries` | option | `--all`, `-a` | no | boolean | false |  |
| `json_output` | option | `--json` | no | boolean | false |  |

<a id="recon-fingerprints-new"></a>
## `recon fingerprints new`

Kind: command
Summary: Scaffold a new fingerprint entry, run checks, print YAML.

| Name | Kind | Tokens | Required | Type | Default | Choices |
|---|---|---|---|---|---|---|
| `slug` | argument | `slug` | yes | text |  |  |
| `name` | option | `--name`, `-n` | yes | text |  |  |
| `category` | option | `--category`, `-c` | no | text | Misc |  |
| `detection_type` | option | `--type`, `-t` | no | text | txt |  |
| `pattern` | option | `--pattern`, `-p` | yes | text |  |  |
| `description` | option | `--description` | no | text |  |  |
| `reference` | option | `--reference` | no | text |  |  |
| `confidence` | option | `--confidence` | no | text | high |  |
| `output` | option | `--output`, `-o` | no | text |  |  |

<a id="recon-fingerprints-search"></a>
## `recon fingerprints search`

Kind: command
Summary: Search fingerprints by slug, name, category, or detection pattern.

| Name | Kind | Tokens | Required | Type | Default | Choices |
|---|---|---|---|---|---|---|
| `query` | argument | `query` | yes | text |  |  |
| `json_output` | option | `--json` | no | boolean | false |  |

<a id="recon-fingerprints-show"></a>
## `recon fingerprints show`

Kind: command
Summary: Show the full definition of a single fingerprint.

| Name | Kind | Tokens | Required | Type | Default | Choices |
|---|---|---|---|---|---|---|
| `slug` | argument | `slug` | yes | text |  |  |
| `json_output` | option | `--json` | no | boolean | false |  |

<a id="recon-fingerprints-test"></a>
## `recon fingerprints test`

Kind: command
Summary: Run one fingerprint against a domain corpus and report which match.

| Name | Kind | Tokens | Required | Type | Default | Choices |
|---|---|---|---|---|---|---|
| `slug` | argument | `slug` | yes | text |  |  |
| `corpus` | option | `--corpus` | no | text |  |  |
| `json_output` | option | `--json` | no | boolean | false |  |

<a id="recon-mcp-doctor"></a>
## `recon mcp doctor`

Kind: command
Summary: End-to-end MCP self-check.

No parameters.

<a id="recon-mcp-install"></a>
## `recon mcp install`

Kind: command
Summary: Install the recon MCP server config into a client's config file.

| Name | Kind | Tokens | Required | Type | Default | Choices |
|---|---|---|---|---|---|---|
| `client` | option | `--client`, `-c` | yes | text |  |  |
| `scope` | option | `--scope`, `-s` | no | text | auto |  |
| `config_path` | option | `--config-path` | no | text |  |  |
| `force` | option | `--force` | no | boolean | false |  |
| `dry_run` | option | `--dry-run` | no | boolean | false |  |

<a id="recon-signals-list"></a>
## `recon signals list`

Kind: command
Summary: List every built-in signal, grouped by category.

| Name | Kind | Tokens | Required | Type | Default | Choices |
|---|---|---|---|---|---|---|
| `category` | option | `--category`, `-c` | no | text |  |  |
| `json_output` | option | `--json` | no | boolean | false |  |

<a id="recon-signals-search"></a>
## `recon signals search`

Kind: command
Summary: Search signals by name, category, description, or candidate slug.

| Name | Kind | Tokens | Required | Type | Default | Choices |
|---|---|---|---|---|---|---|
| `query` | argument | `query` | yes | text |  |  |
| `json_output` | option | `--json` | no | boolean | false |  |

<a id="recon-signals-show"></a>
## `recon signals show`

Kind: command
Summary: Show the full definition of a single signal.

| Name | Kind | Tokens | Required | Type | Default | Choices |
|---|---|---|---|---|---|---|
| `name` | argument | `name` | yes | text |  |  |
| `json_output` | option | `--json` | no | boolean | false |  |
