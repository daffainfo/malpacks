#!/usr/bin/env python3
"""Rebuild database.json from the upstream malicious package feeds.

Sources:
    ossf     OSV MAL-* advisories, downloaded as one snapshot tarball
    datadog  npm and PyPI manifests
    curated  records already in database.json from no managed source

Usage:
    python3 .github/scripts/build_database.py
    python3 .github/scripts/build_database.py --output /tmp/db.json --no-readme
    python3 .github/scripts/build_database.py --source ossf
"""

import argparse
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

OSSF_TARBALL = "https://codeload.github.com/ossf/malicious-packages/tar.gz/refs/heads/main"
OSSF_URL = "https://github.com/ossf/malicious-packages"
DATADOG_MANIFEST = (
    "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset"
    "/main/samples/%s/manifest.json"
)
DATADOG_URL = "https://github.com/DataDog/malicious-software-packages-dataset"

MANAGED_SOURCES = ("ossf", "datadog")
SOURCE_RANK = {"ossf": 0, "datadog": 1, "curated": 2}

# OSV ecosystem -> the ids used in database.json
ECOSYSTEM_MAP = {
    "npm": "npm",
    "PyPI": "pypi",
    "RubyGems": "gem",
    "Go": "go",
    "crates.io": "cargo",
    "Maven": "maven",
    "NuGet": "nuget",
    "Packagist": "composer",
}

ECOSYSTEM_LABELS = {
    "npm": "npm", "pypi": "PyPI", "gem": "RubyGems", "go": "Go", "cargo": "crates.io",
    "maven": "Maven", "nuget": "NuGet", "composer": "Packagist", "vscode": "VS Code",
}

COUNTS_START = "<!-- malpacks:counts:start -->"
COUNTS_END = "<!-- malpacks:counts:end -->"

# Guard rails: refuse to publish a database that looks broken.
MIN_RECORDS = 5000
MAX_SHRINK_RATIO = 0.80
SIZE_WARNING_MB = 45

_PYPI_SEPARATORS = re.compile(r"[-_.]+")


def log(message):
    sys.stderr.write("[build] %s\n" % message)
    sys.stderr.flush()


def normalize_name(ecosystem, name):
    name = (name or "").strip()
    if ecosystem == "pypi":
        return _PYPI_SEPARATORS.sub("-", name).lower()
    if ecosystem in ("go", "maven"):
        return name
    return name.lower()


def download(url, destination, attempts=3, timeout=300):
    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "malpacks-db-builder"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                with open(destination, "wb") as handle:
                    shutil.copyfileobj(response, handle)
            return destination
        except (urllib.error.URLError, OSError) as exc:
            last_error = exc
            log("attempt %d/%d failed for %s: %s" % (attempt, attempts, url, exc))
            if attempt < attempts:
                time.sleep(5 * attempt)
    raise RuntimeError("could not download %s: %s" % (url, last_error))


# --------------------------------------------------------------------------
# sources
# --------------------------------------------------------------------------

def from_ossf(tarball=None, workdir=None):
    """Records from the OpenSSF malicious-packages OSV corpus."""
    cleanup = False
    if tarball is None:
        handle, tarball = tempfile.mkstemp(dir=workdir, prefix="ossf-", suffix=".tar.gz")
        os.close(handle)
        cleanup = True
        log("downloading %s" % OSSF_TARBALL)
        download(OSSF_TARBALL, tarball)
        log("downloaded %.1f MB" % (os.path.getsize(tarball) / 1e6))

    records, skipped = [], 0
    try:
        with tarfile.open(tarball, "r:gz") as archive:
            for member in archive:
                if not member.isfile():
                    continue
                path = member.name.split("/", 1)[-1]
                if not (path.startswith("osv/malicious/") and path.endswith(".json")):
                    continue
                try:
                    advisory = json.load(archive.extractfile(member))
                except (ValueError, OSError):
                    skipped += 1
                    continue
                if advisory.get("withdrawn"):
                    continue
                identifier = advisory.get("id")
                if not identifier:
                    skipped += 1
                    continue
                published = (advisory.get("published") or advisory.get("modified") or "")[:10]
                for affected in advisory.get("affected") or []:
                    package = affected.get("package") or {}
                    raw_ecosystem = package.get("ecosystem") or ""
                    name = package.get("name")
                    if not name:
                        continue
                    ecosystem = ECOSYSTEM_MAP.get(raw_ecosystem)
                    if ecosystem is None:
                        if raw_ecosystem.startswith("VSCode"):
                            ecosystem = "vscode"
                        else:
                            skipped += 1
                            continue
                    record = {
                        "type": ecosystem,
                        "name": name,
                        "id": identifier,
                        "published": published,
                        "source": "ossf",
                    }
                    versions = sorted({str(item) for item in (affected.get("versions") or []) if item})
                    if versions:
                        record["versions"] = versions
                    records.append(record)
    finally:
        if cleanup and os.path.exists(tarball):
            os.remove(tarball)

    log("ossf: %d records (%d skipped)" % (len(records), skipped))
    return records


def from_datadog(workdir=None):
    """Records from the Datadog dataset. Dates come from stabilize_dates()."""
    records = []
    for ecosystem, folder in (("npm", "npm"), ("pypi", "pypi")):
        handle, temporary = tempfile.mkstemp(dir=workdir, prefix="datadog-", suffix=".json")
        os.close(handle)
        try:
            download(DATADOG_MANIFEST % folder, temporary)
            with open(temporary, "r", encoding="utf-8") as fh:
                manifest = json.load(fh)
        except (RuntimeError, ValueError, OSError) as exc:
            log("datadog %s: skipped (%s)" % (folder, exc))
            continue
        finally:
            if os.path.exists(temporary):
                os.remove(temporary)

        if not isinstance(manifest, dict):
            continue
        for name, versions in manifest.items():
            record = {
                "type": ecosystem,
                "name": name,
                "url": DATADOG_URL,
                "source": "datadog",
            }
            if isinstance(versions, list) and versions:
                record["versions"] = sorted({str(item) for item in versions if item})
            records.append(record)
    log("datadog: %d records" % len(records))
    return records


def read_previous(path):
    """The database as it stands now, keyed by package."""
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            entries = json.load(handle)
    except (ValueError, OSError) as exc:
        log("existing database unreadable, starting fresh (%s)" % exc)
        return {}
    if not isinstance(entries, list):
        return {}

    previous = {}
    for entry in entries:
        if isinstance(entry, dict) and entry.get("name") and entry.get("type"):
            previous[(entry["type"], normalize_name(entry["type"], entry["name"]))] = entry
    return previous


def from_existing(previous):
    """Records that did not come from a managed source, kept as curated."""
    curated = []
    for entry in previous.values():
        if entry.get("source") in MANAGED_SOURCES:
            continue  # regenerated from upstream on every run
        record = dict(entry)
        record["source"] = "curated"
        curated.append(record)
    log("curated: %d records kept from the previous database" % len(curated))
    return curated


def stabilize_dates(records, previous):
    """Give undated records a stable "first seen" date.

    The Datadog dataset carries no disclosure dates, so only packages missing
    from yesterday's database are stamped, and the date is then carried forward
    untouched. A bootstrap run stamps nothing: the whole dataset would look like
    it was disclosed on the same day.
    """
    bootstrap = not any(entry.get("source") in MANAGED_SOURCES for entry in previous.values())
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    stamped = 0
    for record in records:
        if record.get("published"):
            continue
        key = (record["type"], normalize_name(record["type"], record["name"]))
        earlier = previous.get(key)
        if earlier is not None:
            if earlier.get("published"):
                record["published"] = earlier["published"]
        elif not bootstrap:
            record["published"] = today
            stamped += 1
    if bootstrap:
        log("dates: bootstrap run, undated records stay undated")
    elif stamped:
        log("dates: %d newly seen records stamped %s" % (stamped, today))
    return records


# --------------------------------------------------------------------------
# merge + write
# --------------------------------------------------------------------------

def merge(groups):
    """Collapse every source down to one record per package.

    The winner is the most authoritative source, then the most recent advisory.
    Only the winning source sets the version scope: versions are unioned within
    it, and one record covering the whole package makes the merged record do the
    same. Weaker sources cannot widen the scope, otherwise the name-only curated
    records would turn "chalk 5.6.1" into "every chalk release".
    """
    groups_by_package = {}
    for source_records in groups:
        for record in source_records:
            ecosystem = record["type"]
            key = (ecosystem, normalize_name(ecosystem, record["name"]))
            groups_by_package.setdefault(key, []).append(record)

    merged, superseded = [], 0
    for candidates in groups_by_package.values():
        candidates.sort(key=_precedence)
        primary = dict(candidates[0])
        superseded += len(candidates) - 1

        rank = SOURCE_RANK.get(primary.get("source"), 9)
        peers = [item for item in candidates if SOURCE_RANK.get(item.get("source"), 9) == rank]
        if all(peer.get("versions") for peer in peers):
            versions = set()
            for peer in peers:
                versions.update(peer["versions"])
            primary["versions"] = sorted(versions)
        else:
            primary.pop("versions", None)
        merged.append(primary)

    if superseded:
        log("merge: %d duplicate records folded into %d packages" % (superseded, len(merged)))

    merged.sort(key=lambda item: (
        item["type"],
        normalize_name(item["type"], item["name"]),
        item.get("id") or "",
    ))
    return merged


def _precedence(record):
    """Sort key that puts the record we want to keep first."""
    return (
        SOURCE_RANK.get(record.get("source"), 9),
        record.get("published", "") == "",          # dated advisories first
        _negate(record.get("published", "")),       # then the most recent
        record.get("id", "") == "",                 # then the one with an id
        -len(record.get("versions") or []),
    )


def _negate(text):
    """Reverse ordering helper for strings inside a tuple sort key."""
    return tuple(-ord(character) for character in text)


FIELD_ORDER = ("type", "name", "id", "published", "versions", "url", "source")


def serialize(records):
    """One JSON object per line so that daily syncs produce readable diffs."""
    lines = []
    for record in records:
        ordered = {key: record[key] for key in FIELD_ORDER if record.get(key)}
        for key in sorted(record):  # keep anything a future source adds
            if key not in ordered and record[key]:
                ordered[key] = record[key]
        lines.append(json.dumps(ordered, separators=(",", ":"), ensure_ascii=False))
    return "[\n" + ",\n".join(lines) + "\n]\n"


def counts_by_ecosystem(records):
    counts = {}
    for record in records:
        counts[record["type"]] = counts.get(record["type"], 0) + 1
    return dict(sorted(counts.items(), key=lambda item: -item[1]))


def counts_by_source(records):
    counts = {}
    for record in records:
        counts[record.get("source", "curated")] = counts.get(record.get("source", "curated"), 0) + 1
    return dict(sorted(counts.items(), key=lambda item: -item[1]))


def write_database(records, path, previous_total):
    payload = serialize(records)
    total = len(records)

    if total < MIN_RECORDS:
        raise RuntimeError("refusing to write %d records (minimum is %d)" % (total, MIN_RECORDS))
    if previous_total and total < previous_total * MAX_SHRINK_RATIO:
        raise RuntimeError(
            "refusing to shrink the database from %d to %d records - upstream looks broken"
            % (previous_total, total)
        )

    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=directory or None, prefix=".database-", suffix=".json")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as fh:
            fh.write(payload)
        json.loads(payload)  # do not publish what we cannot read back
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)

    size_mb = len(payload.encode("utf-8")) / 1e6
    if size_mb > SIZE_WARNING_MB:
        log("WARNING: database.json is %.1f MB - consider sharding it per ecosystem" % size_mb)
    return size_mb


def write_meta(records, path, size_mb, sources):
    meta = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total": len(records),
        "size_mb": round(size_mb, 2),
        "ecosystems": counts_by_ecosystem(records),
        "sources": counts_by_source(records),
        "upstream": [
            {"name": "ossf", "url": OSSF_URL},
            {"name": "datadog", "url": DATADOG_URL},
        ] if "ossf" in sources or "datadog" in sources else [],
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(meta, handle, indent=2)
        handle.write("\n")
    return meta


def update_readme(path, records, meta):
    """Refresh the counts block in the README."""
    if not os.path.exists(path):
        return False
    with open(path, "r", encoding="utf-8") as handle:
        content = handle.read()

    counts = counts_by_ecosystem(records)
    rows = ["| Ecosystem | Malicious packages |", "| --- | ---: |"]
    for ecosystem, count in counts.items():
        rows.append("| %s | %s |" % (ECOSYSTEM_LABELS.get(ecosystem, ecosystem), "{:,}".format(count)))
    rows.append("| **Total** | **%s** |" % "{:,}".format(len(records)))
    block = "%s\n%s\n\n_Last synced: %s_\n%s" % (
        COUNTS_START, "\n".join(rows), meta["generated_at"], COUNTS_END
    )

    if COUNTS_START in content and COUNTS_END in content:
        updated = re.sub(
            re.escape(COUNTS_START) + r".*?" + re.escape(COUNTS_END), lambda _: block, content, flags=re.DOTALL
        )
    else:
        pattern = r"(## Total malicious packages\n)(.*?)(?=\n## |\Z)"
        if not re.search(pattern, content, flags=re.DOTALL):
            return False
        updated = re.sub(pattern, lambda match: match.group(1) + block + "\n", content, flags=re.DOTALL)

    if updated == content:
        return False
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(updated)
    return True


def emit_github_output(values):
    destination = os.environ.get("GITHUB_OUTPUT")
    if not destination:
        return
    with open(destination, "a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write("%s=%s\n" % (key, value))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    repository = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    parser.add_argument("--output", default=os.path.join(repository, "database.json"))
    parser.add_argument("--readme", default=os.path.join(repository, "README.md"))
    parser.add_argument("--no-readme", action="store_true", help="do not touch the README")
    parser.add_argument("--source", action="append", choices=["ossf", "datadog"], dest="sources",
                        help="limit the run to one source (repeatable)")
    parser.add_argument("--ossf-tarball", help="use a local snapshot instead of downloading")
    parser.add_argument("--workdir", help="directory for temporary downloads")
    args = parser.parse_args(argv)

    sources = args.sources or ["ossf", "datadog"]
    previous = read_previous(args.output)
    previous_total = len(previous)

    groups = []
    if "ossf" in sources:
        groups.append(from_ossf(tarball=args.ossf_tarball, workdir=args.workdir))
    if "datadog" in sources:
        groups.append(from_datadog(workdir=args.workdir))
    groups.append(from_existing(previous))

    records = stabilize_dates(merge(groups), previous)
    size_mb = write_database(records, args.output, previous_total)
    meta = write_meta(records, os.path.splitext(args.output)[0] + ".meta.json", size_mb, sources)
    if not args.no_readme:
        update_readme(args.readme, records, meta)

    delta = len(records) - previous_total
    summary = "%s records (%+d), %.1f MB - %s" % (
        "{:,}".format(len(records)), delta, size_mb,
        ", ".join("%s %s" % (ECOSYSTEM_LABELS.get(key, key), "{:,}".format(value))
                  for key, value in list(meta["ecosystems"].items())[:5]),
    )
    log(summary)
    emit_github_output({
        "total": len(records),
        "delta": delta,
        "summary": summary,
        "size_mb": "%.1f" % size_mb,
    })
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
