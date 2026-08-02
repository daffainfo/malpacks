"""Globally installed npm packages."""

import json
import subprocess

from packages import Dependency

LOCATION = "npm (installed)"


def installed():
    """Return the globally installed npm packages as Dependency records."""
    result = _run(["npm", "ls", "-g", "--depth=0", "--json"])
    if result is None:
        return []

    try:
        payload = json.loads(result)
    except ValueError:
        return _parse_tree(_run(["npm", "ls", "-g", "--depth=0"]) or "")

    dependencies = []
    for name, meta in (payload.get("dependencies") or {}).items():
        version = meta.get("version") if isinstance(meta, dict) else None
        dependencies.append(Dependency("npm", name, version, LOCATION))
    return dependencies


def _parse_tree(output):
    """Fallback for npm versions that do not support --json."""
    dependencies = []
    for line in output.splitlines():
        line = line.strip().replace("├──", "").replace("└──", "").replace("+--", "").replace("`--", "").strip()
        if not line or line.startswith("/") or " " in line:
            continue
        # Scoped packages keep their leading @: @scope/name@1.2.3
        prefix, separator, version = line.rpartition("@")
        if not separator or not prefix:
            prefix, version = line, None
        dependencies.append(Dependency("npm", prefix, version, LOCATION))
    return dependencies


def _run(command):
    try:
        # npm exits non-zero on unmet peer deps but still prints a usable tree.
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.stdout.strip() else None


def list_all_npm_packages():
    """Backwards compatible helper: names only."""
    return [dependency.name for dependency in installed()]
