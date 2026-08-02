"""Turning collected dependencies into findings."""

from core.report import Finding
from packages import gem, manifests, npm, pypi

COLLECTORS = {
    "npm": npm.installed,
    "pypi": pypi.installed,
    "gem": gem.installed,
}


def evaluate(dependencies, db, include_unaffected=False):
    """Match every dependency against the database."""
    findings, seen = [], set()
    for dependency in dependencies:
        for match in db.match(
            dependency.ecosystem, dependency.name, dependency.version,
            include_unaffected=include_unaffected,
        ):
            key = (
                dependency.ecosystem, dependency.name, dependency.version,
                match.advisory or match.url, dependency.location,
            )
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(dependency, match))
    return findings


def scan_installed(ecosystems, db, include_unaffected=False):
    """Check installed packages. Returns (findings, dependencies, checked),
    where checked lists the managers that actually answered."""
    dependencies, checked = [], []
    for ecosystem in ecosystems:
        collector = COLLECTORS.get(ecosystem)
        if collector is None:
            continue
        collected = collector()
        if collected:
            checked.append(ecosystem)
        dependencies.extend(collected)
    return evaluate(dependencies, db, include_unaffected), dependencies, checked


def scan_paths(paths, db, max_depth=12, include_unaffected=False):
    """Check projects under paths. Returns (findings, dependencies, files)."""
    dependencies, files = manifests.collect(paths, max_depth=max_depth)
    return evaluate(dependencies, db, include_unaffected), dependencies, files
