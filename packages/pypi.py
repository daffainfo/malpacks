"""Installed Python distributions."""

import subprocess
import sys

from packages import Dependency

LOCATION = "pip (installed)"


def installed():
    """Return the installed Python distributions as Dependency records."""
    for command in (
        [sys.executable, "-m", "pip", "freeze", "--all"],
        ["pip3", "freeze", "--all"],
        ["pip", "freeze", "--all"],
    ):
        output = _run(command)
        if output:
            return _parse_freeze(output)
    return []


def _parse_freeze(output):
    dependencies = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if line.startswith("Warning") or line.startswith("WARNING"):
            continue
        if "==" in line:
            name, _, version = line.partition("==")
        elif " @ " in line:  # direct URL install: name @ file:///...
            name, version = line.split(" @ ", 1)[0], None
        else:
            name, version = line, None
        name = name.strip()
        if name:
            dependencies.append(Dependency("pypi", name, (version or "").strip() or None, LOCATION))
    return dependencies


def _run(command):
    try:
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def list_all_pypi_packages():
    """Backwards compatible helper: names only."""
    return [dependency.name for dependency in installed()]
