"""Command line for zcheck: scan (default), diff, audit."""

import argparse
import os
import sys

from . import __version__
from .common import Output, ZcheckError, note, use_syslog
from .config import DEFAULT_PATH, Config

SUBCOMMANDS = ("scan", "diff", "audit")

TOP_HELP = """\
Filesystem integrity inventory checked against dpkg's package metadata.

  zcheck [scan]                 record a run in DIR/runs/, point DIR/latest.db at it
  zcheck diff [OLD NEW]         compare two runs (default: previous vs latest)
  zcheck audit [RUN]            check one run against package metadata

Bare `zcheck` (or with only scan options) runs a scan. With --syslog, all
output goes to syslog under the tag "zcheck" instead of the terminal: one
line per finding at warning (alarm), notice or info level, then a summary
line with the counts. Errors are also printed to stderr. Settings and
classification rules are in one file, /etc/zcheck.conf by default; an
annotated example is /usr/share/zcheck/zcheck.conf.example.
Run `zcheck COMMAND --help` for each command's options and output.
"""

SCAN_HELP = """\
Walk the filesystem and write one SQLite file per run to DIR/runs/<host>-<time>.db.
DIR/latest.db is pointed at it only once the run is complete, so a run that
dies partway never appears there. A full host is roughly 300k entries and
100 MB per run.

Each entry records type, mode, uid, gid, size, mtime and the sha256 (files),
link target (symlinks), device number (devices) or filesystem type (mount
points). Paths are stored as exact bytes. It also records the owning dpkg
package(s), following merged /usr, dpkg-divert and update-alternatives.
For package files it records whether the content matches dpkg's checksum and
whether the file is a conffile, and it stores every installed package's
version, so a diff can tell an upgrade from tampering.

Only real disk filesystems are walked (see 'fstype' in the config). Anything
else (proc, tmpfs, overlay, nfs, squashfs...) is recorded as one "M" entry,
so a new mount shows up in the diff. Files that vanish mid-run, for example
during an apt upgrade, are logged but are not errors.

Exit: 0 clean, 1 some entries couldn't be read, 2 error.
"""

AUDIT_HELP = """\
Check one run against package metadata:
  alarm   files that don't match their package checksum (setuid/setgid ones
          say so), setuid/setgid files no package owns, and device nodes
          outside /dev
  notice  modified conffiles, files that couldn't be hashed, and package
          setuid/setgid files with no checksum to verify them against
Unmodified package setuid/setgid files aren't listed. --unowned adds files
no package owns (outside /etc), for taking inventory.

"""

OUTPUT_HELP = """\
Items are grouped under ALARM / NOTICE / EXPLAINED, and each states facts:

  ~ /usr/bin/other
      changed:  content, checksum ok->mismatch
      owner:    pkgb 1.0 (checksum mismatch)

First line: + added, - removed, ~ changed (* in audit), then the path.
changed: the fields that differ: content (sha256), mode, uid, gid,
  type, target (symlink), rdev (device number), fstype (mount type),
  checksum (against the package) and conffile status. For added, removed
  and audit items this line is entry: or was:, showing "TYPE MODE UID:GID"
  plus the symlink target, device number or mount type. TYPE is F file,
  L symlink, D directory, M unscanned mount, C/B char/block device, P fifo,
  S socket.
owner: the owning package(s) and version ("a -> b" if it changed between
  runs), or "none", then the package checksum or conffile state.
rule: shown only when a rule (built-in default or config) decided the class.

In --json output the same facts are "detail", "owner" and "rule", plus a
"reason" string explaining the class.

Classes:
  alarm      needs a look: an unexplained change to a package-owned or
             unowned path, setuid/setgid added, a file that doesn't match its
             package checksum, a device node outside /dev
  notice     expected kinds of change worth seeing: conffiles, /etc,
             alternatives with no package change, snaps
  explained  accounted for: the owning package's version changed between the
             runs, or a known generated file changed while packages changed
             (initramfs, ld.so.cache, __pycache__, ...)
Rules in the config (ignore/notice/alarm/generated GLOB) are checked first.

Exit: 0 no alarms, 1 alarms (or notices too with --strict), 2 error.
"""


def build_parser() -> argparse.ArgumentParser:
    fmt = argparse.RawDescriptionHelpFormatter

    # Options accepted before or after the subcommand. SUPPRESS on the copies
    # so a subcommand doesn't reset a value given before it.
    def shared(defaults: bool) -> argparse.ArgumentParser:
        p = argparse.ArgumentParser(add_help=False)
        d = (lambda v: v) if defaults else (lambda v: argparse.SUPPRESS)
        p.add_argument("-c", "--config", default=d(DEFAULT_PATH),
                       help=f"config file (default {DEFAULT_PATH})")
        p.add_argument("-d", "--dir", default=d("/var/lib/zcheck"),
                       help="state directory with runs/ and latest.db (default /var/lib/zcheck)")
        p.add_argument("--syslog", action="store_true", default=d(False),
                       help="send all output to syslog (tag zcheck), one line per item; "
                            "errors also go to stderr")
        return p

    ap = argparse.ArgumentParser(prog="zcheck", description=TOP_HELP, formatter_class=fmt,
                                 parents=[shared(True)])
    ap.add_argument("--version", action="version", version=f"zcheck {__version__}")
    sub = ap.add_subparsers(dest="command", metavar="COMMAND")

    s = sub.add_parser("scan", parents=[shared(False)], formatter_class=fmt,
                       description=SCAN_HELP, help="record a run (default)")
    s.add_argument("-o", "--output", help="write the run to FILE instead of DIR/runs/")
    s.add_argument("--keep", type=int, default=7, help="runs to keep in DIR/runs (default 7)")
    s.add_argument("--root", action="append", default=[],
                   help="scan this instead of / (repeatable; config includes are ignored)")
    s.add_argument("--dpkg-admindir", default="/var/lib/dpkg", help=argparse.SUPPRESS)

    d = sub.add_parser("diff", parents=[shared(False)], formatter_class=fmt,
                       description="Compare two runs.\n\n" + OUTPUT_HELP, help="compare two runs")
    d.add_argument("runs", nargs="*", metavar="RUN", help="OLD NEW (default: the latest two in DIR/runs)")
    d.add_argument("--all", action="store_true", help="also list explained changes")
    d.add_argument("--json", action="store_true", help="machine-readable output")
    d.add_argument("--strict", action="store_true", help="notices count as alarms for the exit code")
    d.add_argument("--allow-host-mismatch", action="store_true",
                   help="compare runs from different hosts (e.g. to check a hot spare for drift)")

    a = sub.add_parser("audit", parents=[shared(False)], formatter_class=fmt,
                       description=AUDIT_HELP + OUTPUT_HELP,
                       help="check one run against package metadata")
    a.add_argument("run", nargs="?", metavar="RUN", help="run file (default DIR/latest.db)")
    a.add_argument("--unowned", action="store_true",
                   help="also list files no package owns (outside /etc)")
    a.add_argument("--json", action="store_true", help="machine-readable output")
    a.add_argument("--strict", action="store_true", help="notices count as alarms for the exit code")
    return ap


def parse_args(argv):
    argv = list(argv)
    # Bare `zcheck`, or only scan options: scan.
    if not any(a in SUBCOMMANDS for a in argv) and not any(
            a in ("-h", "--help", "--version") for a in argv):
        argv.insert(0, "scan")
    return build_parser().parse_args(argv)


def main(argv=None) -> int:
    os.umask(0o077)
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.syslog and getattr(args, "json", False):
        print("zcheck: --json and --syslog can't be combined", file=sys.stderr)
        return 2
    out = use_syslog("zcheck") if args.syslog else Output()
    try:
        cfg = Config.load(args.config)
        if args.command == "scan":
            from .scan import scan_command
            return scan_command(cfg, args)
        from .compare import audit_command, diff_command
        if args.command == "diff":
            return diff_command(cfg, args, out)
        return audit_command(cfg, args, out)
    except ZcheckError as e:
        print(f"zcheck: {e}", file=sys.stderr)
        if args.syslog:
            note(str(e), "err")
        return 2
    except KeyboardInterrupt:
        return 130
