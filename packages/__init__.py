"""Package collectors: what is installed locally, and what a project declares."""

from collections import namedtuple

# One dependency seen somewhere. version is None when only a range was pinned,
# location is a manifest path or "<manager> (installed)".
Dependency = namedtuple("Dependency", ["ecosystem", "name", "version", "location"])

__all__ = ["Dependency"]
