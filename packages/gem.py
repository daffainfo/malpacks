"""Installed Ruby gems."""

import re
import subprocess

from packages import Dependency

LOCATION = "gem (installed)"

# "rake (13.0.6, 12.3.3)" -> name plus every installed version
_GEM_LINE = re.compile(r"^(?P<name>[\w.\-]+)\s*(?:\((?P<versions>[^)]*)\))?$")


def installed():
    """Return the installed gems as Dependency records, one per version."""
    output = _run(["gem", "list", "--local"])
    if output is None:
        return []

    dependencies = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("*"):
            continue
        matched = _GEM_LINE.match(line)
        if not matched:
            continue
        name = matched.group("name")
        raw_versions = matched.group("versions") or ""
        versions = [item.strip().split(" ")[0] for item in raw_versions.split(",") if item.strip()]
        if not versions:
            dependencies.append(Dependency("gem", name, None, LOCATION))
        for version in versions:
            dependencies.append(Dependency("gem", name, version, LOCATION))
    return dependencies


def _run(command):
    try:
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def list_all_gem_packages():
    """Backwards compatible helper: names only."""
    return sorted({dependency.name for dependency in installed()})
