"""Command line interface."""

import argparse
import os
import sys
from datetime import date, timedelta

from core import database, report, scanner
from core.database import Database, DatabaseError
from core.report import Palette
from core.version import AUTHOR, NAME, URL, VERSION

EXIT_OK = 0
EXIT_FOUND = 1
EXIT_USAGE = 2
EXIT_DATABASE = 3

DEFAULT_ECOSYSTEMS = ("npm", "pypi", "gem")

DEFAULTS = {
    "db": None,
    "format": "table",
    "output": None,
    "ecosystem": None,
    "silent": False,
    "no_color": False,
    "fail_on_found": False,
    "only_malicious": False,
    "ignore": None,
}


def banner():
    """Kept as a module level helper for backwards compatibility."""
    print(_banner_text(Palette(_color_enabled(False))))


def _banner_text(palette):
    art = """
 #    #    ##    #       #####     ##     ####   #    #   ####
 ##  ##   #  #   #       #    #   #  #   #    #  #   #   #
 # ## #  #    #  #       #    #  #    #  #       ####     ####
 #    #  ######  #       #####   ######  #       #  #         #
 #    #  #    #  #       #       #    #  #    #  #   #   #    #
 #    #  #    #  ######  #       #    #   ####   #    #   ####
"""
    tagline = "malicious package intelligence for npm, PyPI, RubyGems and friends"
    return "%s\n%s\n%s\n" % (
        palette.blue(art.rstrip("\n")),
        palette.dim("  " + tagline),
        palette.dim("  v%s  %s  by %s" % (VERSION, URL, AUTHOR)),
    )


# --------------------------------------------------------------------------
# argument parsing
# --------------------------------------------------------------------------

def _common_parser():
    """Flags shared by the root parser and every subcommand."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--db", metavar="PATH", default=argparse.SUPPRESS,
                        help="use a specific database.json")
    common.add_argument("-f", "--format", choices=("table", "json", "csv", "sarif"),
                        default=argparse.SUPPRESS, help="output format (default: table)")
    common.add_argument("-o", "--output", metavar="FILE", default=argparse.SUPPRESS,
                        help="write the report to a file instead of stdout")
    common.add_argument("-e", "--ecosystem", metavar="NAME", default=argparse.SUPPRESS,
                        help="restrict to one ecosystem (npm, pypi, gem, go, cargo, maven, nuget, composer)")
    common.add_argument("--only-malicious", action="store_true", default=argparse.SUPPRESS,
                        help="hide findings whose version could not be confirmed")
    common.add_argument("--ignore", metavar="FILE", default=argparse.SUPPRESS,
                        help="file of 'ecosystem:name' lines to suppress")
    common.add_argument("--fail-on-found", action="store_true", default=argparse.SUPPRESS,
                        help="exit 1 when anything is found (for CI)")
    common.add_argument("--silent", action="store_true", default=argparse.SUPPRESS,
                        help="suppress the banner and progress notes")
    common.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS,
                        help="disable ANSI colours")
    return common


def build_parser():
    common = _common_parser()
    parser = argparse.ArgumentParser(
        prog=NAME,
        parents=[common],
        description="Find malicious packages in your projects and on your machine.",
        epilog="Run '%s <command> --help' for command specific options." % NAME,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="store_true", help="show the version and exit")
    # Legacy flags from malpacks 1.x, still accepted.
    parser.add_argument("--all", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--packages", type=str, default="", help=argparse.SUPPRESS)

    commands = parser.add_subparsers(dest="command", metavar="<command>")

    scan_cmd = commands.add_parser("scan", parents=[common], help="scan project manifests, lockfiles and SBOMs")
    scan_cmd.add_argument("paths", nargs="*", default=["."], metavar="PATH",
                          help="files or directories to scan (default: .)")
    scan_cmd.add_argument("-d", "--depth", type=int, default=12, help="directory recursion limit")

    env_cmd = commands.add_parser("env", parents=[common], help="scan the packages installed on this machine")
    env_cmd.add_argument("--all", action="store_true", help="check every supported package manager")
    env_cmd.add_argument("--packages", type=str, default="", metavar="LIST",
                         help="comma separated managers to check, e.g. npm,pypi")

    check_cmd = commands.add_parser("check", parents=[common], help="look up packages by name")
    check_cmd.add_argument("refs", nargs="*", metavar="REF",
                           help="ecosystem:name[@version], or a bare name; reads stdin when omitted")

    search_cmd = commands.add_parser("search", parents=[common], help="search advisories by package name")
    search_cmd.add_argument("query", metavar="QUERY")
    search_cmd.add_argument("-n", "--limit", type=int, default=50, help="maximum results (0 = no limit)")

    feed_cmd = commands.add_parser("feed", parents=[common], help="recently disclosed malicious packages")
    feed_cmd.add_argument("--since", default="7d", metavar="WINDOW",
                          help="time window: 24h, 7d, 4w, all (default: 7d)")
    feed_cmd.add_argument("-n", "--limit", type=int, default=25, help="maximum results (0 = no limit)")

    github_cmd = commands.add_parser("github", parents=[common],
                                     help="audit GitHub repositories via their dependency graph")
    github_cmd.add_argument("target", nargs="?", metavar="TARGET",
                            help="owner/repo, an org or user, or nothing for your own repos")
    github_cmd.add_argument("-n", "--limit", type=int, default=0,
                            help="maximum repositories (default: 100 with a token, 10 without)")

    commands.add_parser("stats", parents=[common], help="database composition and freshness")

    update_cmd = commands.add_parser("update", parents=[common], help="download the latest database")
    update_cmd.add_argument("--url", default=database.REMOTE_DATABASE, help="source URL")
    update_cmd.add_argument("--timeout", type=int, default=180, help="download timeout in seconds")

    commands.add_parser("version", parents=[common], help="show the version and exit")
    return parser


def _apply_defaults(args):
    for key, value in DEFAULTS.items():
        if not hasattr(args, key):
            setattr(args, key, value)
    return args


def _color_enabled(disabled):
    if disabled or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

def main(argv=None):
    parser = build_parser()
    args = _apply_defaults(parser.parse_args(argv))

    structured = args.format in ("json", "csv", "sarif")
    palette = Palette(_color_enabled(args.no_color or (structured and not args.output)))

    if args.version or args.command == "version":
        print("%s %s" % (NAME, VERSION))
        return EXIT_OK

    if not args.silent and not structured:
        print(_banner_text(palette))

    ecosystem = None
    if args.ecosystem:
        ecosystem = database.resolve_ecosystem(args.ecosystem)
        if ecosystem is None:
            _error(palette, "unknown ecosystem: %s" % args.ecosystem)
            _error(palette, "known ecosystems: %s" % ", ".join(sorted(database.ECOSYSTEMS)))
            return EXIT_USAGE

    command = args.command
    if command is None:
        # malpacks 1.x invocation styles keep working.
        if args.all or args.packages:
            command = "env"
        else:
            return _dashboard(args, palette, ecosystem)

    try:
        if command == "scan":
            return _scan(args, palette, ecosystem)
        if command == "env":
            return _env(args, palette, ecosystem)
        if command == "check":
            return _check(args, palette, ecosystem)
        if command == "github":
            return _github(args, palette, ecosystem)
        if command == "search":
            return _search(args, palette, ecosystem)
        if command == "feed":
            return _feed(args, palette, ecosystem)
        if command == "stats":
            return _stats(args, palette)
        if command == "update":
            return _update(args, palette)
    except DatabaseError as exc:
        _error(palette, str(exc))
        return EXIT_DATABASE
    except KeyboardInterrupt:
        _error(palette, "interrupted")
        return EXIT_USAGE

    parser.print_help()
    return EXIT_USAGE


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def _scan(args, palette, ecosystem):
    db = Database.load(args.db)
    _note(args, palette, "scanning %s against %s advisories"
          % (", ".join(args.paths), _thousands(len(db))))

    findings, dependencies, files = scanner.scan_paths(args.paths, db, max_depth=args.depth)
    findings = _filter(findings, ecosystem, args.only_malicious, args.ignore)

    if not files:
        _note(args, palette, "no manifests, lockfiles or SBOMs found")
    scanned = "%s from %s" % (
        _plural(len(dependencies), "dependency", "dependencies"), _plural(len(files), "file")
    )
    context = None
    if any(dependency.version is None for dependency in dependencies):
        context = "tip: commit a lockfile so versions resolve exactly"
    return _emit(args, palette, findings, db, scanned, context,
                 {"paths": args.paths, "files": len(files), "dependencies": len(dependencies)})


def _env(args, palette, ecosystem):
    db = Database.load(args.db)
    selected, unknown = _selected_ecosystems(args, ecosystem)
    if unknown:
        _error(palette, "unknown package manager: %s" % ", ".join(unknown))
        _error(palette, "supported: %s" % ", ".join(DEFAULT_ECOSYSTEMS))
        return EXIT_USAGE

    _note(args, palette, "checking installed packages: %s" % ", ".join(selected))
    findings, dependencies, checked = scanner.scan_installed(selected, db)
    findings = _filter(findings, ecosystem, args.only_malicious, args.ignore)

    for missing in [item for item in selected if item not in checked]:
        _note(args, palette, "%s: no packages reported (is the package manager installed?)" % missing)

    scanned = "%s installed" % _plural(len(dependencies), "package")
    if checked:
        scanned += " across %s" % ", ".join(checked)
    return _emit(args, palette, findings, db, scanned, None,
                 {"managers": checked, "dependencies": len(dependencies)})


def _github(args, palette, ecosystem):
    from core import github

    db = Database.load(args.db)
    try:
        targets = github.resolve_targets(args.target, args.limit)
    except github.GitHubError as exc:
        _error(palette, str(exc))
        return EXIT_DATABASE
    if not targets:
        _error(palette, "no repositories to audit")
        return EXIT_USAGE

    if not github.token():
        _note(args, palette, "no GITHUB_TOKEN set - limited to public repositories and 60 requests/hour")
    _note(args, palette, "fetching dependency graphs for %d %s"
          % (len(targets), "repository" if len(targets) == 1 else "repositories"))

    dependencies, scanned, failures = github.dependencies(targets)
    findings = _filter(scanner.evaluate(dependencies, db), ecosystem, args.only_malicious, args.ignore)

    for repository, reason in sorted(failures.items()):
        _note(args, palette, "%s: %s" % (repository, reason))

    scanned_text = "%s from %s of %s" % (
        _plural(len(dependencies), "dependency", "dependencies"),
        len(scanned), _plural(len(targets), "repository", "repositories"),
    )
    return _emit(args, palette, findings, db, scanned_text, None,
                 {"repositories": scanned, "failed": failures, "dependencies": len(dependencies)})


def _check(args, palette, ecosystem):
    db = Database.load(args.db)
    refs = list(args.refs)
    if not refs and not sys.stdin.isatty():
        refs = [line.strip() for line in sys.stdin if line.strip()]
    if not refs:
        _error(palette, "nothing to check - pass a package reference or pipe a list on stdin")
        return EXIT_USAGE

    from packages import Dependency

    findings, clean = [], []
    for ref in refs:
        parsed_ecosystem, name, version = _parse_ref(ref, ecosystem)
        dependency = Dependency(parsed_ecosystem or "", name, version, "<check>")
        matches = db.match(parsed_ecosystem, name, version, include_unaffected=True)
        confirmed = [match for match in matches if match.verdict != database.NOT_AFFECTED]
        if confirmed:
            for match in confirmed:
                findings.append(report.Finding(
                    Dependency(match.ecosystem, match.name, version, "<check>"), match
                ))
        else:
            clean.append((dependency, matches))

    findings = _filter(findings, ecosystem, args.only_malicious, args.ignore)

    if args.format == "table":
        lines = []
        for dependency, matches in clean:
            coordinate = "%s%s" % (
                "%s:" % dependency.ecosystem if dependency.ecosystem else "", dependency.name
            )
            if dependency.version:
                coordinate += "@%s" % dependency.version
            if matches:
                lines.append("%s %s %s" % (
                    palette.green("[+]"), coordinate,
                    palette.dim("- listed, but the malicious versions are %s"
                                % ", ".join(matches[0].affected_versions or [])),
                ))
            else:
                lines.append("%s %s %s" % (palette.green("[+]"), coordinate,
                                           palette.dim("- not in the database")))
        text = report.render_table(findings, palette)
        if lines:
            text = ("\n".join(lines) + "\n\n" + text) if findings else "\n".join(lines)
        report.write_output(text, args.output)
    else:
        _emit_structured(args, palette, findings, db, {"refs": refs})

    return _exit_code(args, findings)


def _search(args, palette, ecosystem):
    db = Database.load(args.db)
    results = db.search(args.query, ecosystem=ecosystem, limit=args.limit)
    if args.format in ("json", "csv"):
        report.write_output(_render_entries(results, args.format), args.output)
        return EXIT_OK

    body = _render_entry_table(results, palette, "no advisories match %r" % args.query)
    if results:
        capped = args.limit and len(results) >= args.limit
        header = "%s %s%s matching %r" % (
            palette.yellow("[*]"), _thousands(len(results)), "+" if capped else "", args.query
        )
        body = header + "\n\n" + body
        if capped:
            body += "\n\n" + palette.dim("    raise --limit to see more")
    report.write_output(body, args.output)
    return EXIT_OK


def _feed(args, palette, ecosystem):
    db = Database.load(args.db)
    since = _since_date(args.since)
    if args.since.lower() not in ("all", "*") and since is None:
        _error(palette, "cannot read time window %r - try 24h, 7d or 4w" % args.since)
        return EXIT_USAGE

    results = db.recent(since=since, ecosystem=ecosystem)
    shown = results[:args.limit] if args.limit else results
    if args.format in ("json", "csv"):
        report.write_output(_render_entries(shown, args.format), args.output)
        return EXIT_OK

    window = "all time" if since is None else "since %s" % since
    header = "%s %s advisories %s%s" % (
        palette.yellow("[*]"), _thousands(len(results)),
        window + (" in %s" % ecosystem if ecosystem else ""),
        palette.dim(" - showing %s" % _thousands(len(shown))) if len(shown) < len(results) else "",
    )
    body = _render_entry_table(shown, palette, "nothing disclosed %s" % window)
    report.write_output(header + "\n\n" + body, args.output)
    return EXIT_OK


def _stats(args, palette):
    db = Database.load(args.db)
    stats = db.stats()
    if args.format in ("json", "csv"):
        import json

        report.write_output(json.dumps(stats, indent=2), args.output)
        return EXIT_OK

    lines = [
        "%s database  : %s" % (palette.yellow("[*]"), stats["path"]),
        "    records  : %s" % _thousands(stats["total"]),
        "    built    : %s" % (stats["generated_at"] or "unknown"),
        "    age      : %s" % (
            "%s day(s)" % stats["age_days"] if stats["age_days"] is not None else "unknown"
        ),
        "    newest   : %s" % (stats["latest_advisory"] or "unknown"),
        "",
    ]
    width = max([len(database.ECOSYSTEMS.get(key, key)) for key in stats["ecosystems"]] or [8])
    for key, count in sorted(stats["ecosystems"].items(), key=lambda item: -item[1]):
        label = database.ECOSYSTEMS.get(key, key)
        lines.append("    %-*s  %s" % (width, label, _thousands(count)))
    lines.append("")
    lines.append("    sources  : %s" % ", ".join(
        "%s (%s)" % (name, _thousands(count))
        for name, count in sorted(stats["sources"].items(), key=lambda item: -item[1])
    ))
    if stats["age_days"] is not None and stats["age_days"] > 7:
        lines.append("")
        lines.append(palette.yellow("[!] database is %s days old - run '%s update'"
                                    % (stats["age_days"], NAME)))
    report.write_output("\n".join(lines), args.output)
    return EXIT_OK


def _update(args, palette):
    _note(args, palette, "downloading %s" % args.url)
    result = database.update(url=args.url, timeout=args.timeout)
    delta = result["added"]
    change = "+%s" % _thousands(delta) if delta > 0 else ("%s" % _thousands(delta) if delta else "no change")
    print("%s database updated: %s records (%s)"
          % (palette.green("[+]"), _thousands(result["total"]), change))
    print("    %s" % palette.dim(result["path"]))
    return EXIT_OK


def _dashboard(args, palette, ecosystem):
    """What you get when malpacks is run with no arguments."""
    try:
        db = Database.load(args.db)
    except DatabaseError as exc:
        _error(palette, str(exc))
        return EXIT_DATABASE

    stats = db.stats()
    week = db.recent(since=_since_date("7d"), ecosystem=ecosystem)
    day = db.recent(since=_since_date("24h"), ecosystem=ecosystem)
    print("%s %s advisories - %s new in the last 7 days, %s in the last 24h"
          % (palette.yellow("[*]"), _thousands(stats["total"]),
             _thousands(len(week)), _thousands(len(day))))
    top = sorted(stats["ecosystems"].items(), key=lambda item: -item[1])[:6]
    print("    %s" % palette.dim(
        "  ".join("%s %s" % (database.ECOSYSTEMS.get(key, key), _thousands(count)) for key, count in top)
    ))
    if stats["age_days"] is not None and stats["age_days"] > 7:
        print("    %s" % palette.yellow("database is %s days old - run '%s update'"
                                        % (stats["age_days"], NAME)))
    print("")
    if week:
        print(_render_entry_table(week[:8], palette, ""))
        print("")
    print(palette.dim("    %s scan .                 scan this project" % NAME))
    print(palette.dim("    %s env --all              scan installed packages" % NAME))
    print(palette.dim("    %s check npm:chalk@5.6.1  look a package up" % NAME))
    print(palette.dim("    %s feed --since 24h       what was just disclosed" % NAME))
    print(palette.dim("    %s --help                 everything else" % NAME))
    return EXIT_OK


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _selected_ecosystems(args, ecosystem):
    """(managers to query, unrecognised names) for the env command."""
    if ecosystem:
        if ecosystem in DEFAULT_ECOSYSTEMS:
            return [ecosystem], []
        return [], [ecosystem]
    raw = getattr(args, "packages", "") or ""
    if not raw:
        return list(DEFAULT_ECOSYSTEMS), []
    selected, unknown = [], []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        resolved = database.resolve_ecosystem(item)
        if resolved in DEFAULT_ECOSYSTEMS:
            selected.append(resolved)
        else:
            unknown.append(item)
    return selected, unknown


def _parse_ref(ref, fallback_ecosystem=None):
    """'npm:@scope/pkg@1.2.3' -> ('npm', '@scope/pkg', '1.2.3')"""
    ref = ref.strip()
    ecosystem = fallback_ecosystem
    head, separator, tail = ref.partition(":")
    if separator:
        resolved = database.resolve_ecosystem(head)
        if resolved:  # 'com.example:artifact' stays a Maven coordinate
            ecosystem, ref = resolved, tail

    version = None
    at = ref.rfind("@")
    if at > 0:
        candidate = ref[at + 1:]
        if candidate and candidate[0].isdigit():
            ref, version = ref[:at], candidate
    return ecosystem, ref, version


def _filter(findings, ecosystem, only_malicious, ignore_path=None):
    if ecosystem:
        findings = [item for item in findings if item.dependency.ecosystem == ecosystem]
    if only_malicious:
        findings = [item for item in findings if item.confirmed]
    ignored = _load_ignore(ignore_path)
    if ignored:
        findings = [item for item in findings if not _is_ignored(item, ignored)]
    return findings


def _load_ignore(path):
    """Read a suppression file: 'ecosystem:name', 'name' or an advisory id."""
    if not path:
        return set()
    try:
        with open(os.path.expanduser(path), "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError as exc:
        raise DatabaseError("cannot read ignore file: %s" % exc)

    ignored = set()
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        entry_ecosystem, name, _version = _parse_ref(line)
        ignored.add((entry_ecosystem or "", database.normalize_name(entry_ecosystem, name)))
    return ignored


def _is_ignored(finding, ignored):
    ecosystem = finding.dependency.ecosystem
    name = database.normalize_name(ecosystem, finding.dependency.name)
    advisory = (finding.match.advisory or "").lower()
    return (
        (ecosystem, name) in ignored
        or ("", name) in ignored
        or ("", advisory) in ignored
    )


def _emit(args, palette, findings, db, scanned, context, scope):
    if args.format == "table":
        report.write_output(report.render_table(findings, palette, scanned, context), args.output)
    else:
        scope = dict(scope or {})
        scope["summary"] = scanned
        _emit_structured(args, palette, findings, db, scope)
    if args.output and not args.silent:
        print("%s report written to %s" % (palette.green("[+]"), args.output))
    return _exit_code(args, findings)


def _emit_structured(args, palette, findings, db, scope):
    if args.format == "json":
        text = report.render_json(findings, db.stats(), scope)
    elif args.format == "csv":
        text = report.render_csv(findings)
    else:
        text = report.render_sarif(findings)
    report.write_output(text, args.output)


def _exit_code(args, findings):
    if args.fail_on_found and findings:
        return EXIT_FOUND
    return EXIT_OK


def _render_entries(entries, output_format):
    if output_format == "csv":
        import csv as csv_module
        import io

        buffer = io.StringIO()
        writer = csv_module.DictWriter(
            buffer, fieldnames=["type", "name", "id", "published", "versions", "url", "source"],
            lineterminator="\n",
        )
        writer.writeheader()
        for entry in entries:
            writer.writerow({
                "type": entry.get("type", ""),
                "name": entry.get("name", ""),
                "id": entry.get("id", ""),
                "published": entry.get("published", ""),
                "versions": ";".join(entry.get("versions") or []),
                "url": database.advisory_url(entry),
                "source": entry.get("source", "curated"),
            })
        return buffer.getvalue()

    import json

    return json.dumps([
        {
            "type": entry.get("type", ""),
            "name": entry.get("name", ""),
            "id": entry.get("id", ""),
            "published": entry.get("published", ""),
            "versions": entry.get("versions"),
            "url": database.advisory_url(entry),
            "source": entry.get("source", "curated"),
        }
        for entry in entries
    ], indent=2)


def _render_entry_table(entries, palette, empty_message):
    if not entries:
        return palette.green("[+] %s" % empty_message) if empty_message else ""
    lines = []
    for entry in entries:
        versions = entry.get("versions")
        scope = ", ".join(versions[:3]) + ("..." if len(versions) > 3 else "") if versions else "all versions"
        lines.append("%s %s %s" % (
            palette.red("[!]"),
            palette.bold("%s:%s" % (entry.get("type", "?"), entry.get("name", "?"))),
            palette.dim("(%s)" % scope),
        ))
        details = database.advisory_url(entry)
        lines.append("    %s%s%s" % (
            entry.get("id", "") or "-",
            "  %s" % entry.get("published", "") if entry.get("published") else "",
            "  %s" % palette.cyan(details) if details else "",
        ))
    return "\n".join(lines)


def _since_date(window):
    """'7d' -> the YYYY-MM-DD 7 days ago; None for 'all' or garbage."""
    window = (window or "").strip().lower()
    if window in ("all", "*", ""):
        return None
    units = {"h": 1.0 / 24, "d": 1.0, "w": 7.0, "m": 30.0, "y": 365.0}
    unit = window[-1]
    if unit.isdigit():
        number, unit = window, "d"
    else:
        number = window[:-1]
    if unit not in units:
        return None
    try:
        days = float(number) * units[unit]
    except ValueError:
        return None
    return (date.today() - timedelta(days=max(0.0, days))).isoformat()


def _thousands(number):
    return "{:,}".format(number)


def _plural(count, singular, plural=None):
    return "%s %s" % (_thousands(count), singular if count == 1 else (plural or singular + "s"))


def _note(args, palette, message):
    if not args.silent and args.format == "table":
        print("%s %s" % (palette.yellow("[*]"), message))


def _error(palette, message):
    sys.stderr.write("%s %s\n" % (palette.red("[!]"), message))
