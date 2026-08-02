"""Pull dependency graphs straight from GitHub.

Every repository with the dependency graph enabled has an SPDX SBOM, so code
does not need checking out. A token is optional for public repositories, but
without one GitHub allows only 60 requests per hour.
"""

import json
import os
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

API = "https://api.github.com"
WORKERS = 6


class GitHubError(Exception):
    """Raised when the GitHub API cannot answer."""


def token():
    for variable in ("GITHUB_TOKEN", "GH_TOKEN", "MALPACKS_GITHUB_TOKEN"):
        value = os.environ.get(variable)
        if value:
            return value.strip()
    return None


def _request(path, timeout=45):
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "malpacks",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    credentials = token()
    if credentials:
        headers["Authorization"] = "Bearer %s" % credentials

    request = urllib.request.Request(API + path, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 403 and not credentials:
            raise GitHubError("rate limited - set GITHUB_TOKEN to raise the limit")
        if exc.code == 404:
            raise GitHubError("not found (or not visible with this token): %s" % path)
        raise GitHubError("GitHub returned %s for %s" % (exc.code, path))
    except (urllib.error.URLError, ValueError) as exc:
        raise GitHubError("GitHub request failed: %s" % exc)


def resolve_targets(target, limit=None):
    """Turn 'owner/repo', 'org' or None into a list of 'owner/repo' strings."""
    default_limit = 100 if token() else 10
    limit = limit or default_limit

    if target and "/" in target:
        return [target.strip("/")]

    if not target:
        user = _request("/user")
        target = user.get("login")
        if not target:
            raise GitHubError("could not determine the authenticated user")
        repositories = _request("/user/repos?per_page=100&sort=updated&affiliation=owner")
    else:
        try:
            repositories = _request("/orgs/%s/repos?per_page=100&sort=updated" % target)
        except GitHubError:
            repositories = _request("/users/%s/repos?per_page=100&sort=updated" % target)

    names = [
        repository["full_name"] for repository in repositories
        if isinstance(repository, dict) and not repository.get("archived")
    ]
    return names[:limit]


def sbom(repository):
    """The SPDX document GitHub generated for a repository."""
    payload = _request("/repos/%s/dependency-graph/sbom" % repository)
    document = payload.get("sbom") if isinstance(payload, dict) else None
    if not document:
        raise GitHubError("%s has no dependency graph SBOM" % repository)
    return document


def dependencies(repositories, on_result=None):
    """Fetch and parse SBOMs concurrently. Returns (dependencies, scanned,
    failures), where failures maps a repository to why it could not be read."""
    from packages.manifests import parse_spdx

    collected, scanned, failures = [], [], {}

    def fetch(repository):
        try:
            return repository, sbom(repository), None
        except GitHubError as exc:
            return repository, None, str(exc)

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for repository, document, error in pool.map(fetch, repositories):
            if error:
                failures[repository] = error
            else:
                parsed = parse_spdx(json.dumps(document), "github://%s" % repository)
                collected.extend(parsed)
                scanned.append(repository)
            if on_result:
                on_result(repository, error)
    return collected, scanned, failures
