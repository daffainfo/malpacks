"""Loading and querying database.json.

One record per line, sorted by (type, name):

    {"type":"npm","name":"chalk","id":"MAL-2025-46969","published":"2025-09-08","versions":["5.6.1"]}

Optional fields: id, published, url (derived from id when missing), source, and
versions. No versions means every version of the package is malicious.
"""

import json
import os
import re
import shutil
import ssl
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone

REMOTE_BASE = "https://raw.githubusercontent.com/daffainfo/malpacks/main"
REMOTE_DATABASE = REMOTE_BASE + "/database.json"
REMOTE_META = REMOTE_BASE + "/database.meta.json"

# Ecosystem ids used in the "type" field, with their display labels.
ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "gem": "RubyGems",
    "go": "Go",
    "cargo": "crates.io",
    "maven": "Maven",
    "nuget": "NuGet",
    "composer": "Packagist",
    "vscode": "VS Code",
}

# Extra spellings accepted on the command line.
ECOSYSTEM_ALIASES = {
    "node": "npm",
    "nodejs": "npm",
    "javascript": "npm",
    "js": "npm",
    "python": "pypi",
    "pip": "pypi",
    "pypy": "pypi",
    "rubygems": "gem",
    "ruby": "gem",
    "gems": "gem",
    "golang": "go",
    "crates": "cargo",
    "crates.io": "cargo",
    "rust": "cargo",
    "packagist": "composer",
    "php": "composer",
    "java": "maven",
    "dotnet": "nuget",
    "nupkg": "nuget",
    "vsx": "vscode",
    "open-vsx": "vscode",
}

# Verdicts attached to a match.
MALICIOUS = "malicious"          # the package (or the exact version) is malicious
UNKNOWN_VERSION = "unverified"   # only some versions are malicious, ours is unknown
NOT_AFFECTED = "not-affected"    # we resolved a version and it is not one of them

_PYPI_SEPARATORS = re.compile(r"[-_.]+")


class DatabaseError(Exception):
    """Raised when the database cannot be located, read or parsed."""


def resolve_ecosystem(value):
    """Map user input onto an ecosystem id, or return None if unknown."""
    if not value:
        return None
    key = value.strip().lower()
    key = ECOSYSTEM_ALIASES.get(key, key)
    return key if key in ECOSYSTEMS else None


def normalize_name(ecosystem, name):
    """Fold a package name the way its registry treats equal names."""
    name = (name or "").strip()
    if ecosystem == "pypi":
        return _PYPI_SEPARATORS.sub("-", name).lower()
    if ecosystem in ("go", "maven"):
        # Module paths and Maven coordinates are case sensitive.
        return name
    return name.lower()


def advisory_url(entry):
    """Best link for an advisory record."""
    url = entry.get("url")
    if url:
        return url
    identifier = entry.get("id", "")
    if identifier.startswith("MAL-") or identifier.startswith("GHSA-"):
        return "https://osv.dev/vulnerability/" + identifier
    return ""


def malicious_versions(entry):
    """Versions known to be malicious, or None when the whole package is."""
    versions = entry.get("versions")
    return list(versions) if versions else None


def _normalize_version(version):
    if version is None:
        return None
    version = str(version).strip().lstrip("=vV")
    return version.split("+", 1)[0] or None


def home_dir():
    """Directory holding the locally cached copy of the database."""
    override = os.environ.get("MALPACKS_HOME")
    if override:
        return os.path.abspath(os.path.expanduser(override))
    return os.path.join(os.path.expanduser("~"), ".malpacks")


def bundled_path():
    """The database.json that ships with the checkout."""
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "database.json")


def cache_path():
    return os.path.join(home_dir(), "database.json")


def meta_path(database_file):
    return os.path.splitext(database_file)[0] + ".meta.json"


def read_meta(database_file):
    """Sidecar metadata written by the sync job, or {} when unavailable."""
    try:
        with open(meta_path(database_file), "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def resolve_path(explicit=None):
    """Pick the database to read: explicit path, then cache, then bundled."""
    if explicit:
        path = os.path.abspath(os.path.expanduser(explicit))
        if not os.path.exists(path):
            raise DatabaseError("database not found: %s" % path)
        return path

    env_path = os.environ.get("MALPACKS_DATABASE")
    if env_path:
        return resolve_path(env_path)

    cached, bundled = cache_path(), bundled_path()
    if os.path.exists(cached):
        if not os.path.exists(bundled) or os.path.getmtime(cached) >= os.path.getmtime(bundled):
            return cached
    if os.path.exists(bundled):
        return bundled
    if os.path.exists(cached):
        return cached
    raise DatabaseError(
        "no database found - run 'python3 main.py update' to download one"
    )


class Match(object):
    """An advisory record paired with the verdict for a concrete version."""

    __slots__ = ("entry", "verdict", "version")

    def __init__(self, entry, verdict, version=None):
        self.entry = entry
        self.verdict = verdict
        self.version = version

    @property
    def ecosystem(self):
        return self.entry.get("type", "")

    @property
    def name(self):
        return self.entry.get("name", "")

    @property
    def advisory(self):
        return self.entry.get("id") or ""

    @property
    def url(self):
        return advisory_url(self.entry)

    @property
    def published(self):
        return self.entry.get("published") or ""

    @property
    def affected_versions(self):
        return malicious_versions(self.entry)


class Database(object):
    """An in-memory index over the advisory records."""

    def __init__(self, entries, path=None):
        self.entries = entries
        self.path = path
        self.meta = read_meta(path) if path else {}
        self._index = {}
        for entry in entries:
            ecosystem = entry.get("type", "")
            key = (ecosystem, normalize_name(ecosystem, entry.get("name", "")))
            self._index.setdefault(key, []).append(entry)

    def __len__(self):
        return len(self.entries)

    @classmethod
    def load(cls, path=None):
        path = resolve_path(path)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                entries = json.load(handle)
        except OSError as exc:
            raise DatabaseError("cannot read %s: %s" % (path, exc))
        except ValueError as exc:
            raise DatabaseError("%s is not valid JSON: %s" % (path, exc))
        if not isinstance(entries, list):
            raise DatabaseError("%s must contain a JSON array of records" % path)
        return cls(entries, path)

    def lookup(self, ecosystem, name):
        """Advisory records for a package, ignoring versions."""
        if ecosystem:
            return list(self._index.get((ecosystem, normalize_name(ecosystem, name)), ()))
        found = []
        for candidate in ECOSYSTEMS:
            found.extend(self._index.get((candidate, normalize_name(candidate, name)), ()))
        return found

    def match(self, ecosystem, name, version=None, include_unaffected=False):
        """Verdicts for a package/version pair, most severe first."""
        version = _normalize_version(version)
        matches = []
        for entry in self.lookup(ecosystem, name):
            affected = malicious_versions(entry)
            if affected is None:
                verdict = MALICIOUS
            elif version is None:
                verdict = UNKNOWN_VERSION
            elif version in {_normalize_version(item) for item in affected}:
                verdict = MALICIOUS
            else:
                verdict = NOT_AFFECTED
            if verdict == NOT_AFFECTED and not include_unaffected:
                continue
            matches.append(Match(entry, verdict, version))
        order = {MALICIOUS: 0, UNKNOWN_VERSION: 1, NOT_AFFECTED: 2}
        matches.sort(key=lambda item: (order[item.verdict], item.entry.get("published", "")), reverse=False)
        return matches

    def search(self, query, ecosystem=None, limit=0):
        """Substring search over package names, or an exact advisory id."""
        needle = query.strip().lower()
        by_advisory = needle.startswith(("mal-", "ghsa-", "snyk-"))
        results = []
        for entry in self.entries:
            if ecosystem and entry.get("type") != ecosystem:
                continue
            if by_advisory:
                hit = needle == (entry.get("id") or "").lower()
            else:
                hit = needle in entry.get("name", "").lower()
            if hit:
                results.append(entry)
                if limit and len(results) >= limit:
                    break
        return results

    def recent(self, since=None, ecosystem=None, limit=0):
        """Advisories published on or after since, a YYYY-MM-DD string."""
        results = []
        for entry in self.entries:
            if ecosystem and entry.get("type") != ecosystem:
                continue
            published = entry.get("published")
            if not published:
                continue
            if since and published < since:
                continue
            results.append(entry)
        results.sort(key=lambda item: (item.get("published", ""), item.get("id", "")), reverse=True)
        return results[:limit] if limit else results

    def stats(self):
        counts = {}
        sources = {}
        latest = ""
        for entry in self.entries:
            counts[entry.get("type", "?")] = counts.get(entry.get("type", "?"), 0) + 1
            sources[entry.get("source", "curated")] = sources.get(entry.get("source", "curated"), 0) + 1
            published = entry.get("published") or ""
            if published > latest:
                latest = published
        return {
            "path": self.path,
            "total": len(self.entries),
            "ecosystems": counts,
            "sources": sources,
            "latest_advisory": latest,
            "generated_at": self.meta.get("generated_at", ""),
            "age_days": self.age_days(),
        }

    def age_days(self):
        """Days since the database was generated, or None if unknown."""
        stamp = self.meta.get("generated_at")
        if stamp:
            try:
                built = datetime.strptime(stamp[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
                return max(0, (datetime.now(timezone.utc) - built).days)
            except ValueError:
                pass
        if self.path and os.path.exists(self.path):
            age = datetime.now().timestamp() - os.path.getmtime(self.path)
            return max(0, int(age // 86400))
        return None


def _download(url, destination, timeout):
    request = urllib.request.Request(url, headers={"User-Agent": "malpacks"})
    context = ssl.create_default_context()
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        with open(destination, "wb") as handle:
            shutil.copyfileobj(response, handle)


def update(url=REMOTE_DATABASE, meta_url=REMOTE_META, timeout=120, destination=None):
    """Download a fresh database into the local cache.

    Raises DatabaseError when the download or its validation fails.
    """
    destination = destination or cache_path()
    directory = os.path.dirname(destination)
    if directory:
        os.makedirs(directory, exist_ok=True)

    previous = 0
    if os.path.exists(destination):
        try:
            with open(destination, "r", encoding="utf-8") as handle:
                previous = len(json.load(handle))
        except (OSError, ValueError):
            previous = 0

    handle, temporary = tempfile.mkstemp(dir=directory or None, prefix=".database-", suffix=".json")
    os.close(handle)
    try:
        _download(url, temporary, timeout)
        with open(temporary, "r", encoding="utf-8") as fh:
            entries = json.load(fh)
        if not isinstance(entries, list) or not entries:
            raise DatabaseError("downloaded database is empty or malformed")
        os.replace(temporary, destination)
    except (urllib.error.URLError, OSError) as exc:
        raise DatabaseError("download failed: %s" % exc)
    except ValueError as exc:
        raise DatabaseError("downloaded database is not valid JSON: %s" % exc)
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)

    if meta_url:
        try:
            _download(meta_url, meta_path(destination), timeout)
        except (urllib.error.URLError, OSError):
            pass  # metadata is optional

    return {
        "path": destination,
        "total": len(entries),
        "added": len(entries) - previous,
        "previous": previous,
    }
