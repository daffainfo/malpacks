"""Parsers for manifests, lockfiles and SBOMs.

Best effort and stdlib only. Unreadable files are skipped, not fatal.
Lockfiles win over manifests because they pin exact versions.
"""

import json
import os
import re
import xml.etree.ElementTree as ElementTree

from packages import Dependency

try:  # Python 3.11+
    import tomllib
except ImportError:  # pragma: no cover - older interpreters fall back to regex
    tomllib = None

# Directories that never contain first-party manifests worth reading.
SKIP_DIRECTORIES = {
    ".bzr", ".git", ".hg", ".idea", ".mypy_cache", ".next", ".nuxt", ".pytest_cache",
    ".svn", ".terraform", ".tox", ".venv", "__pycache__", "bower_components", "build",
    "dist", "env", "node_modules", "site-packages", "target", "venv", "vendor",
}

MAX_FILE_BYTES = 64 * 1024 * 1024

# purl type -> ecosystem id
PURL_TYPES = {
    "npm": "npm", "pypi": "pypi", "gem": "gem", "golang": "go", "cargo": "cargo",
    "maven": "maven", "nuget": "nuget", "composer": "composer", "vscode": "vscode",
}

_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:(?P<operator>===|==)\s*(?P<version>[^\s;#,]+))?"
)
_GO_REQUIRE = re.compile(r"^(?P<name>[^\s]+)\s+(?P<version>v[^\s/]+)")
_GEMFILE_SPEC = re.compile(r"^ {4}(?P<name>[A-Za-z0-9._\-!]+) \((?P<version>[^)]+)\)$")
_PNPM_PACKAGE = re.compile(r"^\s{2,6}/?(?P<name>(?:@[^/\s]+/)?[^@/\s:'\"]+)[@/](?P<version>\d[\w.+-]*)[:(\s]")
_TOML_PACKAGE = re.compile(
    r"\[\[package\]\][^\[]*?name\s*=\s*\"(?P<name>[^\"]+)\"[^\[]*?version\s*=\s*\"(?P<version>[^\"]+)\"",
    re.DOTALL,
)


def scan_tree(root, max_depth=12):
    """Yield manifest paths under root, or root itself when it is a file."""
    root = os.path.abspath(os.path.expanduser(root))
    if os.path.isfile(root):
        if handler_for(os.path.basename(root)):
            yield root
        return

    base_depth = root.rstrip(os.sep).count(os.sep)
    for directory, subdirectories, filenames in os.walk(root):
        if directory.rstrip(os.sep).count(os.sep) - base_depth >= max_depth:
            subdirectories[:] = []
            continue
        subdirectories[:] = [
            name for name in subdirectories
            if name not in SKIP_DIRECTORIES and not name.startswith(".cache")
        ]
        for filename in filenames:
            if handler_for(filename):
                yield os.path.join(directory, filename)


def handler_for(filename):
    """Return the parser for a file name, or None when it is not a manifest."""
    lowered = filename.lower()
    if lowered in _EXACT:
        return _EXACT[lowered]
    if lowered.endswith((".cdx.json", ".cyclonedx.json")) or lowered in ("bom.json", "sbom.json"):
        return parse_cyclonedx
    if lowered.endswith(".spdx.json"):
        return parse_spdx
    if lowered.startswith("requirements") and lowered.endswith(".txt"):
        return parse_requirements
    if lowered.startswith("constraints") and lowered.endswith(".txt"):
        return parse_requirements
    return None


def parse(path):
    """Parse one manifest into Dependency records; never raises."""
    handler = handler_for(os.path.basename(path))
    if handler is None:
        return []
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return []
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            content = handle.read()
    except OSError:
        return []

    try:
        dependencies = handler(content, path)
    except Exception:  # one bad file must not end the scan
        return []

    seen, unique = set(), []
    for dependency in dependencies:
        if not dependency.name:
            continue
        key = (dependency.ecosystem, dependency.name, dependency.version)
        if key in seen:
            continue
        seen.add(key)
        unique.append(dependency)
    return unique


def collect(paths, max_depth=12):
    """Parse every manifest under paths, returning (dependencies, files).

    A directory with a lockfile skips its loose manifest, which would only add
    version-less duplicates.
    """
    discovered = []
    for path in paths:
        discovered.extend(scan_tree(path, max_depth=max_depth))

    discovered = sorted(set(discovered))
    locked_directories = {}
    for path in discovered:
        name = os.path.basename(path).lower()
        if name in _LOCKFILES:
            locked_directories.setdefault(os.path.dirname(path), set()).add(_LOCKFILES[name])

    dependencies, files = [], []
    for path in discovered:
        name = os.path.basename(path).lower()
        shadowed_by = _SHADOWED.get(name)
        if shadowed_by and shadowed_by in locked_directories.get(os.path.dirname(path), ()):
            continue
        parsed = parse(path)
        if parsed:
            dependencies.extend(parsed)
            files.append(path)
    return dependencies, files


# --------------------------------------------------------------------------
# npm
# --------------------------------------------------------------------------

def parse_package_lock(content, path):
    payload = json.loads(content)
    dependencies = []

    # lockfileVersion 2/3
    for key, meta in (payload.get("packages") or {}).items():
        if not key or not isinstance(meta, dict):
            continue  # the "" key is the project itself
        name = meta.get("name") or key.split("node_modules/")[-1]
        dependencies.append(Dependency("npm", name, meta.get("version"), path))

    # lockfileVersion 1 (and the legacy mirror kept by v2)
    def walk(tree):
        for name, meta in (tree or {}).items():
            if not isinstance(meta, dict):
                continue
            dependencies.append(Dependency("npm", name, meta.get("version"), path))
            walk(meta.get("dependencies"))

    walk(payload.get("dependencies"))
    return dependencies


def parse_package_json(content, path):
    payload = json.loads(content)
    dependencies = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, specifier in (payload.get(section) or {}).items():
            dependencies.append(Dependency("npm", name, _exact_or_none(specifier), path))
    return dependencies


def parse_yarn_lock(content, path):
    dependencies, pending = [], []
    for line in content.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" ") and line.rstrip().endswith(":"):
            pending = [_yarn_name(spec) for spec in line.rstrip()[:-1].split(", ")]
            continue
        stripped = line.strip()
        if pending and (stripped.startswith("version ") or stripped.startswith("version:")):
            version = stripped.split(":", 1)[-1] if stripped.startswith("version:") else stripped[len("version "):]
            version = version.strip().strip('"')
            for name in pending:
                dependencies.append(Dependency("npm", name, version or None, path))
            pending = []
    return dependencies


def _yarn_name(spec):
    spec = spec.strip().strip('"')
    # "@scope/name@npm:^1.0.0" -> "@scope/name"
    at = spec.rfind("@")
    return spec[:at] if at > 0 else spec


def parse_pnpm_lock(content, path):
    dependencies = []
    inside = False
    for line in content.splitlines():
        if not line.startswith(" ") and line.rstrip().endswith(":"):
            inside = line.strip().rstrip(":") in ("packages", "snapshots")
            continue
        if not inside:
            continue
        matched = _PNPM_PACKAGE.match(line)
        if matched:
            dependencies.append(Dependency("npm", matched.group("name"), matched.group("version"), path))
    return dependencies


# --------------------------------------------------------------------------
# Python
# --------------------------------------------------------------------------

def parse_requirements(content, path):
    dependencies = []
    for line in content.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-") or "://" in line:
            continue
        matched = _REQUIREMENT.match(line)
        if matched:
            dependencies.append(Dependency("pypi", matched.group("name"), matched.group("version"), path))
    return dependencies


def parse_pipfile_lock(content, path):
    payload = json.loads(content)
    dependencies = []
    for section in ("default", "develop"):
        for name, meta in (payload.get(section) or {}).items():
            version = (meta or {}).get("version") if isinstance(meta, dict) else None
            dependencies.append(Dependency("pypi", name, _exact_or_none(version), path))
    return dependencies


def parse_poetry_lock(content, path):
    return [Dependency("pypi", name, version, path) for name, version in _toml_packages(content)]


def parse_uv_lock(content, path):
    return [Dependency("pypi", name, version, path) for name, version in _toml_packages(content)]


def parse_pyproject(content, path):
    dependencies = []
    data = _load_toml(content)
    if data is None:
        return dependencies

    for specifier in (data.get("project") or {}).get("dependencies") or []:
        matched = _REQUIREMENT.match(str(specifier).strip())
        if matched:
            dependencies.append(Dependency("pypi", matched.group("name"), matched.group("version"), path))
    for group in ((data.get("project") or {}).get("optional-dependencies") or {}).values():
        for specifier in group or []:
            matched = _REQUIREMENT.match(str(specifier).strip())
            if matched:
                dependencies.append(Dependency("pypi", matched.group("name"), matched.group("version"), path))

    poetry = ((data.get("tool") or {}).get("poetry") or {})
    for section in ("dependencies", "dev-dependencies"):
        for name, specifier in (poetry.get(section) or {}).items():
            if name.lower() == "python":
                continue
            if isinstance(specifier, dict):
                specifier = specifier.get("version")
            dependencies.append(Dependency("pypi", name, _exact_or_none(specifier), path))
    return dependencies


# --------------------------------------------------------------------------
# Other ecosystems
# --------------------------------------------------------------------------

def parse_gemfile_lock(content, path):
    dependencies = []
    for line in content.splitlines():
        matched = _GEMFILE_SPEC.match(line.rstrip())
        if matched:
            version = matched.group("version").split(" ")[0].split(",")[0]
            dependencies.append(Dependency("gem", matched.group("name"), version, path))
    return dependencies


def parse_gemspec_free(content, path):  # Gemfile without a lock: names only
    dependencies = []
    for match in re.finditer(r"^\s*gem\s+['\"]([^'\"]+)['\"]", content, re.MULTILINE):
        dependencies.append(Dependency("gem", match.group(1), None, path))
    return dependencies


def parse_go_mod(content, path):
    dependencies, inside = [], False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            inside = True
            continue
        if inside and stripped == ")":
            inside = False
            continue
        if stripped.startswith("require "):
            stripped = stripped[len("require "):]
        elif not inside:
            continue
        stripped = stripped.split("//", 1)[0].strip()
        matched = _GO_REQUIRE.match(stripped)
        if matched:
            dependencies.append(Dependency("go", matched.group("name"), matched.group("version").lstrip("v"), path))
    return dependencies


def parse_go_sum(content, path):
    dependencies = []
    for line in content.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].startswith("v"):
            version = parts[1].split("/")[0].lstrip("v")
            dependencies.append(Dependency("go", parts[0], version, path))
    return dependencies


def parse_cargo_lock(content, path):
    return [Dependency("cargo", name, version, path) for name, version in _toml_packages(content)]


def parse_composer_lock(content, path):
    payload = json.loads(content)
    dependencies = []
    for section in ("packages", "packages-dev"):
        for package in payload.get(section) or []:
            if isinstance(package, dict):
                version = (package.get("version") or "").lstrip("v") or None
                dependencies.append(Dependency("composer", package.get("name"), version, path))
    return dependencies


def parse_composer_json(content, path):
    payload = json.loads(content)
    dependencies = []
    for section in ("require", "require-dev"):
        for name, specifier in (payload.get(section) or {}).items():
            if "/" not in name:  # php, ext-*, lib-*
                continue
            dependencies.append(Dependency("composer", name, _exact_or_none(specifier), path))
    return dependencies


def parse_nuget_lock(content, path):
    payload = json.loads(content)
    dependencies = []
    for framework in (payload.get("dependencies") or {}).values():
        for name, meta in (framework or {}).items():
            version = (meta or {}).get("resolved") if isinstance(meta, dict) else None
            dependencies.append(Dependency("nuget", name, version, path))
    return dependencies


def parse_packages_config(content, path):
    root = ElementTree.fromstring(content)
    return [
        Dependency("nuget", element.get("id"), element.get("version"), path)
        for element in root.iter("package")
        if element.get("id")
    ]


def parse_pom(content, path):
    root = ElementTree.fromstring(content)
    namespace = ""
    if root.tag.startswith("{"):
        namespace = root.tag[: root.tag.index("}") + 1]
    dependencies = []
    for element in root.iter(namespace + "dependency"):
        group = element.findtext(namespace + "groupId")
        artifact = element.findtext(namespace + "artifactId")
        version = element.findtext(namespace + "version")
        if not group or not artifact:
            continue
        if version and version.startswith("${"):
            version = None
        dependencies.append(Dependency("maven", "%s:%s" % (group.strip(), artifact.strip()), version, path))
    return dependencies


# --------------------------------------------------------------------------
# SBOMs
# --------------------------------------------------------------------------

def parse_cyclonedx(content, path):
    payload = json.loads(content)
    dependencies = []

    def walk(components):
        for component in components or []:
            if not isinstance(component, dict):
                continue
            dependency = _from_purl(component.get("purl"), path)
            if dependency:
                dependencies.append(dependency)
            walk(component.get("components"))

    walk(payload.get("components"))
    walk([payload.get("metadata", {}).get("component")] if payload.get("metadata") else [])
    return dependencies


def parse_spdx(content, path):
    payload = json.loads(content)
    dependencies = []
    for package in payload.get("packages") or []:
        if not isinstance(package, dict):
            continue
        for reference in package.get("externalRefs") or []:
            dependency = _from_purl((reference or {}).get("referenceLocator"), path)
            if dependency:
                dependencies.append(dependency)
    return dependencies


def _from_purl(purl, path):
    """pkg:npm/%40scope%2Fname@1.2.3 -> Dependency('npm', '@scope/name', '1.2.3')"""
    if not purl or not str(purl).startswith("pkg:"):
        return None
    body = str(purl)[4:].split("?", 1)[0].split("#", 1)[0]
    kind, _, remainder = body.partition("/")
    ecosystem = PURL_TYPES.get(kind.lower())
    if not ecosystem or not remainder:
        return None
    name, _, version = remainder.rpartition("@")
    if not name:
        name, version = remainder, ""
    name = _unquote(name)
    if ecosystem == "maven":
        name = name.replace("/", ":", 1)
    return Dependency(ecosystem, name, _unquote(version) or None, path)


def _unquote(value):
    try:
        from urllib.parse import unquote

        return unquote(value)
    except Exception:
        return value


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _exact_or_none(specifier):
    """Keep a version only when the specifier pins one exactly."""
    if not specifier or not isinstance(specifier, str):
        return None
    specifier = specifier.strip()
    if specifier.startswith("=="):
        specifier = specifier[2:].strip()
    elif specifier.startswith("="):
        specifier = specifier[1:].strip()
    if not specifier or specifier[0] not in "0123456789":
        return None
    if any(character in specifier for character in "^~*<>| ,"):
        return None
    return specifier


def _load_toml(content):
    if tomllib is None:
        return None
    try:
        return tomllib.loads(content)
    except Exception:
        return None


def _toml_packages(content):
    """(name, version) pairs from a [[package]] style lockfile."""
    data = _load_toml(content)
    if data is not None:
        packages = data.get("package") or []
        if isinstance(packages, list):
            return [
                (item.get("name"), item.get("version"))
                for item in packages
                if isinstance(item, dict) and item.get("name")
            ]
    return [(match.group("name"), match.group("version")) for match in _TOML_PACKAGE.finditer(content)]


_EXACT = {
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "package.json": parse_package_json,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "bun.lock": parse_yarn_lock,
    "pipfile.lock": parse_pipfile_lock,
    "poetry.lock": parse_poetry_lock,
    "uv.lock": parse_uv_lock,
    "pyproject.toml": parse_pyproject,
    "gemfile.lock": parse_gemfile_lock,
    "gemfile": parse_gemspec_free,
    "go.mod": parse_go_mod,
    "go.sum": parse_go_sum,
    "cargo.lock": parse_cargo_lock,
    "composer.lock": parse_composer_lock,
    "composer.json": parse_composer_json,
    "packages.lock.json": parse_nuget_lock,
    "packages.config": parse_packages_config,
    "pom.xml": parse_pom,
}

# Lockfiles that make the loose manifest in the same directory redundant.
_LOCKFILES = {
    "package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm", "bun.lock": "npm",
    "poetry.lock": "pypi", "uv.lock": "pypi", "pipfile.lock": "pypi",
    "gemfile.lock": "gem", "composer.lock": "composer", "go.sum": "go",
}
_SHADOWED = {
    "package.json": "npm",
    "pyproject.toml": "pypi",
    "gemfile": "gem",
    "composer.json": "composer",
    "go.mod": "go",
}
