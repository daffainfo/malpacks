"""Findings and the ways they get printed."""

import csv
import io
import json
import os
import sys
from datetime import datetime, timezone

from colorama import Fore, Style

from core import database
from core.version import NAME, URL, VERSION

VERDICT_LABEL = {
    database.MALICIOUS: "MALICIOUS",
    database.UNKNOWN_VERSION: "UNVERIFIED",
    database.NOT_AFFECTED: "NOT AFFECTED",
}


class Palette(object):
    """Colour helper that collapses to plain text when colour is off."""

    def __init__(self, enabled=True):
        self.enabled = enabled

    def paint(self, colour, text):
        return "%s%s%s" % (colour, text, Style.RESET_ALL) if self.enabled else str(text)

    def red(self, text):
        return self.paint(Fore.RED, text)

    def green(self, text):
        return self.paint(Fore.GREEN, text)

    def yellow(self, text):
        return self.paint(Fore.YELLOW, text)

    def blue(self, text):
        return self.paint(Fore.BLUE, text)

    def cyan(self, text):
        return self.paint(Fore.CYAN, text)

    def dim(self, text):
        return "%s%s%s" % (Style.DIM, text, Style.RESET_ALL) if self.enabled else str(text)

    def bold(self, text):
        return "%s%s%s" % (Style.BRIGHT, text, Style.RESET_ALL) if self.enabled else str(text)

    def verdict(self, verdict):
        label = VERDICT_LABEL.get(verdict, verdict.upper())
        if verdict == database.MALICIOUS:
            return self.red(label)
        if verdict == database.UNKNOWN_VERSION:
            return self.yellow(label)
        return self.green(label)


class Finding(object):
    """A dependency that matched an advisory."""

    __slots__ = ("dependency", "match")

    def __init__(self, dependency, match):
        self.dependency = dependency
        self.match = match

    @property
    def verdict(self):
        return self.match.verdict

    @property
    def confirmed(self):
        return self.match.verdict == database.MALICIOUS

    def as_dict(self):
        return {
            "ecosystem": self.dependency.ecosystem,
            "package": self.dependency.name,
            "version": self.dependency.version,
            "verdict": self.match.verdict,
            "advisory": self.match.advisory,
            "published": self.match.published,
            "malicious_versions": self.match.affected_versions,
            "url": self.match.url,
            "source": self.match.entry.get("source", "curated"),
            "location": self.dependency.location,
        }


def summarize(findings):
    summary = {"total": len(findings), "malicious": 0, "unverified": 0, "ecosystems": {}}
    for finding in findings:
        if finding.confirmed:
            summary["malicious"] += 1
        elif finding.verdict == database.UNKNOWN_VERSION:
            summary["unverified"] += 1
        ecosystem = finding.dependency.ecosystem
        summary["ecosystems"][ecosystem] = summary["ecosystems"].get(ecosystem, 0) + 1
    return summary


def sort_key(finding):
    order = {database.MALICIOUS: 0, database.UNKNOWN_VERSION: 1, database.NOT_AFFECTED: 2}
    return (
        order.get(finding.verdict, 3),
        finding.dependency.ecosystem,
        finding.dependency.name.lower(),
        finding.dependency.version or "",
    )


# --------------------------------------------------------------------------
# renderers
# --------------------------------------------------------------------------

def render_table(findings, palette, scanned=None, context=None):
    lines = []
    if not findings:
        lines.append(palette.green("[+] No malicious packages found."))
        if scanned:
            lines.append(palette.dim("    %s" % scanned))
        return "\n".join(lines)

    for finding in sorted(findings, key=sort_key):
        dependency, match = finding.dependency, finding.match
        coordinate = "%s:%s" % (dependency.ecosystem, dependency.name)
        if dependency.version:
            coordinate += "@%s" % dependency.version
        marker = palette.red("[!]") if finding.confirmed else palette.yellow("[?]")
        lines.append("%s %s  %s" % (marker, palette.bold(coordinate), palette.verdict(finding.verdict)))
        if match.advisory:
            lines.append("    advisory : %s%s" % (match.advisory, "  (%s)" % match.published if match.published else ""))
        affected = match.affected_versions
        if affected:
            shown = ", ".join(affected[:6]) + (" (+%d more)" % (len(affected) - 6) if len(affected) > 6 else "")
            lines.append("    affected : %s" % shown)
        else:
            lines.append("    affected : all versions")
        if match.url:
            lines.append("    details  : %s" % palette.cyan(match.url))
        lines.append("    seen in  : %s" % palette.dim(dependency.location))
        lines.append("")

    summary = summarize(findings)
    lines.append(palette.red(
        "[!] %d malicious, %d unverified across %d %s"
        % (summary["malicious"], summary["unverified"], len(summary["ecosystems"]),
           "ecosystem" if len(summary["ecosystems"]) == 1 else "ecosystems")
    ))
    if scanned:
        lines.append(palette.dim("    %s" % scanned))
    if context:
        lines.append(palette.dim("    %s" % context))
    return "\n".join(lines)


def render_json(findings, database_stats=None, scanned=None):
    payload = {
        "schema": "malpacks/1",
        "tool": {"name": NAME, "version": VERSION},
        "generated_at": _now(),
        "database": database_stats or {},
        "scanned": scanned or {},
        "summary": summarize(findings),
        "findings": [finding.as_dict() for finding in sorted(findings, key=sort_key)],
    }
    return json.dumps(payload, indent=2)


def render_csv(findings):
    buffer = io.StringIO()
    columns = [
        "ecosystem", "package", "version", "verdict", "advisory", "published",
        "malicious_versions", "url", "source", "location",
    ]
    writer = csv.DictWriter(buffer, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    for finding in sorted(findings, key=sort_key):
        row = finding.as_dict()
        row["malicious_versions"] = ";".join(row["malicious_versions"] or [])
        writer.writerow(row)
    return buffer.getvalue()


def render_sarif(findings, root=None):
    rules, rule_index, results = [], {}, []
    for finding in sorted(findings, key=sort_key):
        data = finding.as_dict()
        rule_id = data["advisory"] or "malpacks/%s/%s" % (data["ecosystem"], data["package"])
        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            rules.append({
                "id": rule_id,
                "name": "MaliciousPackage",
                "shortDescription": {"text": "Malicious package: %s (%s)" % (data["package"], data["ecosystem"])},
                "fullDescription": {"text": _describe(data)},
                "helpUri": data["url"] or URL,
                "properties": {"tags": ["supply-chain", "malicious-package", data["ecosystem"]]},
            })
        results.append({
            "ruleId": rule_id,
            "ruleIndex": rule_index[rule_id],
            "level": "error" if finding.confirmed else "warning",
            "message": {"text": _describe(data)},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _relative(data["location"], root)},
                    "region": {"startLine": 1},
                }
            }],
            "properties": {
                "ecosystem": data["ecosystem"],
                "package": data["package"],
                "version": data["version"],
                "verdict": data["verdict"],
            },
        })

    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": NAME,
                "version": VERSION,
                "informationUri": URL,
                "rules": rules,
            }},
            "results": results,
        }],
    }, indent=2)


def _describe(data):
    coordinate = "%s:%s" % (data["ecosystem"], data["package"])
    if data["version"]:
        coordinate += "@%s" % data["version"]
    if data["verdict"] == database.MALICIOUS:
        return "%s is a known malicious package (%s)." % (coordinate, data["advisory"] or data["source"])
    affected = ", ".join(data["malicious_versions"] or []) or "unknown"
    return (
        "%s matches an advisory affecting version(s) %s, but the installed version could "
        "not be resolved - verify manually." % (coordinate, affected)
    )


def _relative(location, root):
    if not location:
        return "unknown"
    if not os.path.isabs(location):
        return location
    try:
        relative = os.path.relpath(location, root or os.getcwd())
    except ValueError:  # different drives on Windows
        return location.replace(os.sep, "/")
    # A path that climbs out of the run root is more useful left absolute.
    if relative.startswith(".."):
        return location.replace(os.sep, "/")
    return relative.replace(os.sep, "/")


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_output(text, path=None):
    """Print to stdout, or write to a file and say where it went."""
    if not path:
        sys.stdout.write(text.rstrip("\n") + "\n")
        return None
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text.rstrip("\n") + "\n")
    return path
