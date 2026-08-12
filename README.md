# Malpacks

Find malicious packages in your projects, on your machine and in your GitHub repositories.

<img src="https://github.com/user-attachments/assets/2d3ed0c6-2a52-473c-8672-a6c1570fbd74" />

## Total malicious packages
<!-- malpacks:counts:start -->
| Ecosystem | Malicious packages |
| --- | ---: |
| npm | 223,360 |
| PyPI | 12,237 |
| RubyGems | 3,513 |
| NuGet | 777 |
| VS Code | 19 |
| Go | 18 |
| crates.io | 10 |
| Maven | 2 |
| Packagist | 1 |
| **Total** | **239,937** |

_Last synced: 2026-08-12T04:14:36Z_
<!-- malpacks:counts:end -->

## Installation

```bash
git clone https://github.com/daffainfo/malpacks
cd malpacks
pip3 install -r requirements.txt
python3 main.py --help
```

## Usage

```bash
python3 main.py                             # recent disclosures
python3 main.py scan .                      # scan a project
python3 main.py scan ~/code ./bom.cdx.json  # trees, single files, SBOMs
python3 main.py env --all                   # installed npm, pip and gem packages
python3 main.py env --packages npm,pypi     # pick the managers
python3 main.py check npm:chalk@5.6.1       # one package
python3 main.py check chalk express         # bare names, all ecosystems
cat suspects.txt | python3 main.py check    # or a piped list
python3 main.py github daffainfo/malpacks   # a repo, an org, or your own repos
python3 main.py feed --since 24h            # what was just disclosed
python3 main.py search MAL-2025-46969       # by name or advisory id
python3 main.py stats                       # database composition
python3 main.py update                      # refresh the database
```

`--all` and `--packages npm,pypi` from malpacks 1.x still work on the root command.

`github` reads the GitHub dependency graph SBOM, so nothing is cloned. Set `GITHUB_TOKEN` for private repos and a higher rate limit.

`update` downloads the newest `database.json` into `~/.malpacks/`, which takes precedence over the bundled copy.

### What `scan` reads

| Ecosystem | Files |
| --- | --- |
| npm | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `package.json` |
| PyPI | `requirements*.txt`, `constraints*.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `pyproject.toml` |
| RubyGems | `Gemfile.lock`, `Gemfile` |
| Go | `go.sum`, `go.mod` |
| crates.io | `Cargo.lock` |
| Packagist | `composer.lock`, `composer.json` |
| NuGet | `packages.lock.json`, `packages.config` |
| Maven | `pom.xml` |
| SBOM | CycloneDX (`*.cdx.json`, `bom.json`) and SPDX (`*.spdx.json`) |

`node_modules`, `.git`, `venv`, `vendor` and `target` are skipped. A directory with a lockfile skips its loose manifest.

## Options

| Flag | Meaning |
| --- | --- |
| `-f, --format table\|json\|csv\|sarif` | output format (default `table`) |
| `-o, --output FILE` | write the report to a file |
| `-e, --ecosystem NAME` | restrict to one ecosystem |
| `--only-malicious` | drop findings whose version could not be confirmed |
| `--ignore FILE` | suppression list of `ecosystem:name`, bare names or advisory ids |
| `--fail-on-found` | exit 1 when anything is found |
| `--silent` | no banner, no progress notes |
| `--no-color` | plain output |
| `--db PATH` | use a specific database (also `MALPACKS_DATABASE`) |

Exit codes: `0` clean, `1` findings with `--fail-on-found`, `2` usage error, `3` database unavailable.

## Verdicts

Advisories record which versions are malicious, and malpacks matches on them. `chalk` and `debug` are normal packages that were backdoored for a few hours in September 2025, so a name-only match would flag every project that ever used them.

| Verdict | Meaning |
| --- | --- |
| `MALICIOUS` | the whole package is malicious, or your exact version is |
| `UNVERIFIED` | only some versions are malicious and yours could not be resolved |
| *(silent)* | your version is not one of the malicious ones |

## In CI

```yaml
- name: Check dependencies
  run: |
    git clone --depth 1 https://github.com/daffainfo/malpacks /tmp/malpacks
    pip3 install -r /tmp/malpacks/requirements.txt
    python3 /tmp/malpacks/main.py scan . \
      --silent --fail-on-found --only-malicious \
      --format sarif --output malpacks.sarif

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: malpacks.sarif
```

## The database

Flat JSON array, one record per line, sorted by ecosystem and name:

```json
{"type":"npm","name":"chalk","id":"MAL-2025-46969","published":"2025-09-08","versions":["5.6.1"],"source":"ossf"}
```

| Field | Notes |
| --- | --- |
| `type` | `npm`, `pypi`, `gem`, `go`, `cargo`, `maven`, `nuget`, `composer`, `vscode` |
| `name` | package name as published on the registry |
| `id` | advisory id, usually an OSV `MAL-*` |
| `published` | disclosure date, `YYYY-MM-DD` |
| `versions` | the malicious versions. Absent means every version is malicious |
| `url` | advisory link. Absent means it is derived from `id` (osv.dev) |
| `source` | `ossf`, `datadog` or `curated` |

Sources are [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages), the [Datadog dataset](https://github.com/DataDog/malicious-software-packages-dataset) and the curated records malpacks started with. One record per package, most authoritative source first, and only that source sets the version scope.

[`update-database.yml`](.github/workflows/update-database.yml) rebuilds it daily at 03:30 UTC and commits only when something changed. To run it yourself:

```bash
python3 .github/scripts/build_database.py
python3 .github/scripts/build_database.py --source ossf --output /tmp/db.json --no-readme
```
