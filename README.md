# Malpacks

Find malicious packages in the projects you build, in the packages installed on your machine, and in the repositories you own.

Malpacks keeps a local copy of every known-malicious package across nine ecosystems, refreshed daily from the [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) corpus and the [Datadog malicious software packages dataset](https://github.com/DataDog/malicious-software-packages-dataset), and matches it against your lockfiles, SBOMs, dependency graphs and installed packages. No API key, no network call at scan time, no runtime dependency beyond `colorama`.

![image](https://github.com/daffainfo/malpacks/assets/36522826/d2983fa6-32f3-454f-92bd-f50b15faca82)

## Total malicious packages
<!-- malpacks:counts:start -->
| Ecosystem | Malicious packages |
| --- | ---: |
| npm | 221,076 |
| PyPI | 12,188 |
| RubyGems | 3,513 |
| NuGet | 777 |
| VS Code | 19 |
| Go | 18 |
| crates.io | 10 |
| Maven | 2 |
| Packagist | 1 |
| **Total** | **237,604** |

_Last synced: 2026-08-02T05:44:07Z_
<!-- malpacks:counts:end -->

The table above is rewritten by the daily sync job, so it always reflects the real content of `database.json`.

## Installation

```bash
git clone https://github.com/daffainfo/malpacks
cd malpacks
pip3 install -r requirements.txt
python3 main.py --help
```

Python 3.8+. The database ships with the repository, so malpacks works offline straight after cloning.

## Quick start

```bash
python3 main.py                       # what was disclosed recently
python3 main.py scan .                # scan this project
python3 main.py env --all             # scan what is installed on this machine
python3 main.py check npm:chalk@5.6.1 # look one package up
python3 main.py update                # pull the newest database
```

## Commands

### `scan`: projects, lockfiles and SBOMs

```bash
python3 main.py scan                        # current directory
python3 main.py scan ~/code ~/work/api      # several trees at once
python3 main.py scan ./package-lock.json    # one file
python3 main.py scan ./bom.cdx.json         # a CycloneDX or SPDX SBOM
```

Malpacks walks the tree (skipping `node_modules`, `.git`, `venv`, `vendor`, `target`, …) and reads everything it recognises:

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

When a directory holds both a lockfile and its loose manifest, only the lockfile is read. It is the one that pins exact versions.

### `env`: installed packages

```bash
python3 main.py env --all               # npm -g, pip, gem
python3 main.py env --packages npm,pypi # pick the managers
```

The malpacks 1.x spelling still works: `python3 main.py --all` and `python3 main.py --packages npm,pypi`.

### `check`: look packages up

```bash
python3 main.py check npm:chalk@5.6.1
python3 main.py check chalk express requests
python3 main.py check npm:@ctrl/tinycolor
cat suspects.txt | python3 main.py check
```

A reference is `ecosystem:name[@version]`, or a bare name to search every ecosystem. Without a version, malpacks tells you the package appears in an advisory but cannot confirm your copy is the malicious one.

### `github`: repositories you do not have checked out

```bash
export GITHUB_TOKEN=ghp_...          # optional for public repos, 60 req/h without
python3 main.py github daffainfo/malpacks
python3 main.py github some-org -n 50
python3 main.py github                # every repo you own
```

Uses the GitHub dependency graph SBOM, so nothing is cloned.

### `feed`, `search`, `stats`

```bash
python3 main.py feed --since 24h        # just disclosed
python3 main.py feed --since 4w -e pypi -n 100
python3 main.py search tinycolor        # by package name
python3 main.py search MAL-2025-46969   # by advisory id
python3 main.py stats                   # database composition and freshness
```

### `update`: refresh the database

```bash
python3 main.py update
```

Downloads the latest `database.json` into `~/.malpacks/` (override with `MALPACKS_HOME`). The cached copy is preferred over the bundled one once it is newer, so you do not have to `git pull` to stay current.

## Options

| Flag | Meaning |
| --- | --- |
| `-f, --format table\|json\|csv\|sarif` | output format (default `table`) |
| `-o, --output FILE` | write the report to a file |
| `-e, --ecosystem NAME` | restrict to one ecosystem |
| `--only-malicious` | drop findings whose version could not be confirmed |
| `--ignore FILE` | suppression list of `ecosystem:name`, a bare name, or an advisory id, with `#` comments |
| `--fail-on-found` | exit 1 when anything is found |
| `--silent` | no banner, no progress notes |
| `--no-color` | plain output |
| `--db PATH` | use a specific database (also `MALPACKS_DATABASE`) |

Exit codes: `0` clean, `1` findings with `--fail-on-found`, `2` usage error, `3` database unavailable.

## Verdicts

Advisories record *which versions* are malicious, and malpacks reports accordingly. This matters: `chalk` and `debug` are ordinary packages that were backdoored for a few hours in September 2025, and a name-only match would flag every project that has ever used them.

| Verdict | Meaning |
| --- | --- |
| `MALICIOUS` | the whole package is malicious, or your exact version is |
| `UNVERIFIED` | only some versions are malicious and yours could not be resolved. Pin a version or commit a lockfile |
| *(silent)* | the package appears in an advisory but your version is not one of the malicious ones |

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

`database.json` is a flat JSON array with one record per line, sorted by ecosystem and name so that daily syncs produce small, readable diffs:

```json
{"type":"npm","name":"chalk","id":"MAL-2025-46969","published":"2025-09-08","versions":["5.6.1"],"source":"ossf"}
```

| Field | Notes |
| --- | --- |
| `type` | `npm`, `pypi`, `gem`, `go`, `cargo`, `maven`, `nuget`, `composer`, `vscode` |
| `name` | package name as published on the registry |
| `id` | advisory id, usually an OSV `MAL-*` |
| `published` | disclosure date, `YYYY-MM-DD` |
| `versions` | the malicious versions. **Absent means every version is malicious** |
| `url` | advisory link. Absent means it is derived from `id` (osv.dev) |
| `source` | `ossf`, `datadog` or `curated` |

`database.meta.json` records when the file was built and what went into it.

### How it stays current

[`.github/workflows/update-database.yml`](.github/workflows/update-database.yml) runs [`build_database.py`](.github/scripts/build_database.py) every day at 03:30 UTC, and on demand from the Actions tab. It downloads the upstream corpora, merges them with the curated records malpacks started with, rewrites `database.json`, `database.meta.json` and the counts table above, and commits only when something actually changed.

Merge rules:

* one record per package. The most authoritative source wins (`ossf` > `datadog` > `curated`), and within it the most recent advisory.
* version scope comes from the winning source alone, so the curated name-only records can never widen `chalk 5.6.1` into "every chalk release".
* curated records are kept unless upstream covers the same package with better metadata.
* the run aborts rather than publishing a database that shrank by more than 20% or fell below 5,000 records.

To rebuild it yourself:

```bash
python3 .github/scripts/build_database.py                 # both sources
python3 .github/scripts/build_database.py --source ossf   # just OpenSSF
python3 .github/scripts/build_database.py --output /tmp/db.json --no-readme
```

## To-Do List
- [x] Scan a file that contains a list of packages
  - [x] Scan requirements.txt (Python)
  - [x] Scan package.json (npm)
- [x] More output options
  - [x] JSON
  - [x] CSV
  - [x] SARIF
- [x] Add more package managers
  - [x] PyPI
  - [x] npm
  - [x] Gem
  - [x] Go
  - [x] Composer
  - [x] Cargo, Maven, NuGet, VS Code extensions
- [x] Add more malicious packages
  - [x] https://blog.phylum.io/phylum-discovers-another-attack-on-pypi/
  - [x] https://www.reversinglabs.com/blog/mining-for-malicious-ruby-gems
  - [x] https://github.com/DataDog/malicious-software-packages-dataset
  - [x] https://github.com/ossf/malicious-packages
- [ ] YAML output
- [ ] Shard `database.json` per ecosystem if it outgrows ~45 MB
