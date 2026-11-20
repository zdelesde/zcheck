"""`zcheck diff` and `zcheck audit`: classify what changed or what's wrong.

Classes:
  alarm      needs a look: unexplained change to a package-owned or unowned
             path, setuid/setgid added, file doesn't match its package
             checksum, device node outside /dev
  notice     expected kinds of change worth seeing: conffiles, /etc,
             alternatives with no package change, snaps
  explained  accounted for: the owning package's version changed between
             the runs, or a known generated file changed alongside package
             changes (initramfs, ld.so.cache, __pycache__, ...)
"""

import fnmatch
import json
import os
import sqlite3
import sys
import urllib.parse

from .common import SCHEMA_VERSION, SETUID_SETGID, ZcheckError, ptext

COMPARED = ("type", "mode", "uid", "gid", "sha256", "target", "rdev", "fstype",
            "md5_status", "conffile")
CLASS_ORDER = ("alarm", "notice", "explained")

DEFAULT_RULES = [
    ("notice", "/snap/*"),
    ("generated", "*/__pycache__"),
    ("generated", "*/__pycache__/*"),
    ("generated", "/boot/initrd.img*"),
    ("generated", "/boot/grub/*"),
    ("generated", "/etc/ld.so.cache"),
    ("generated", "/etc/ssl/certs/*"),
    ("generated", "/usr/lib/modules/*/modules.*"),
    ("generated", "/lib/modules/*/modules.*"),
    ("generated", "/usr/lib/locale/locale-archive"),
    ("generated", "/usr/share/mime/*"),
    ("generated", "/usr/share/info/dir*"),
    ("generated", "*/icon-theme.cache"),
    ("generated", "*/gdk-pixbuf-2.0/*/loaders.cache"),
    ("generated", "*/giomodule.cache"),
    ("generated", "*/immodules.cache"),
    ("generated", "*/graphviz/config*"),
    ("generated", "/usr/share/glib-2.0/schemas/gschemas.compiled"),
    ("notice", "/etc/*"),
]


# ------------------------------------------------------------------------ input

def ro_uri(path: str) -> str:
    return "file:" + urllib.parse.quote(os.path.abspath(path)) + "?mode=ro"


def open_runs(new: str, old: str = None) -> sqlite3.Connection:
    for p in (new, old):
        if p and not os.path.exists(p):
            raise ZcheckError(f"{p}: no such file")
    db = sqlite3.connect(ro_uri(new), uri=True)
    db.row_factory = sqlite3.Row
    if old:
        db.execute("ATTACH DATABASE ? AS o", (ro_uri(old),))
    return db


def run_info(db, schema: str, path: str) -> dict:
    try:
        row = db.execute(f"SELECT * FROM {schema}.run").fetchone()
    except sqlite3.DatabaseError as e:
        raise ZcheckError(f"{path}: not a zcheck run ({e})")
    if row is None:
        raise ZcheckError(f"{path}: no run record")
    info = dict(row)
    if info["schema_version"] != SCHEMA_VERSION:
        raise ZcheckError(f"{path}: schema version {info['schema_version']}, expected {SCHEMA_VERSION}")
    if not info["finished"]:
        raise ZcheckError(f"{path}: run didn't finish")
    info["file"] = path
    return info


def latest_two(state_dir: str):
    runs_dir = os.path.join(state_dir, "runs")
    try:
        runs = sorted(f for f in os.listdir(runs_dir) if f.endswith(".db") and not f.startswith("."))
    except OSError as e:
        raise ZcheckError(f"{runs_dir}: {e.strerror}")
    if len(runs) < 2:
        raise ZcheckError(f"{runs_dir}: need two runs to compare (have {len(runs)}); try 'zcheck audit'")
    return os.path.join(runs_dir, runs[-2]), os.path.join(runs_dir, runs[-1])


def packages(db, schema: str) -> dict:
    return {r["name"]: r["version"] for r in db.execute(f"SELECT name, version FROM {schema}.package")
            if not r["name"].startswith("(")}


def owners(db, schema: str, path: bytes) -> list:
    return [r[0] for r in db.execute(
        f"SELECT p.name FROM {schema}.owner w JOIN {schema}.package p ON p.id = w.package_id "
        f"WHERE w.path = ? ORDER BY 1", (path,))]


def first_match(rules: list, path: str):
    for action, pattern in rules:
        if fnmatch.fnmatchcase(path, pattern):
            return action, pattern
    return None


# ------------------------------------------------------------------- formatting

def describe(e) -> str:
    """'TYPE MODE UID:GID' plus target, device number or mount type."""
    s = f"{e['type']} {e['mode']:04o} {e['uid']}:{e['gid']}"
    if e["type"] == "L":
        s += f" -> {ptext(e['target'])}"
    elif e["type"] in ("C", "B"):
        s += f" {e['rdev']}"
    elif e["type"] == "M":
        s += f" {e['fstype']}"
    elif e["type"] == "F" and e["sha256"] and e["sha256"].startswith("!"):
        s += f" (couldn't hash: {e['sha256'][1:]})"
    return s


def field_changes(o, n) -> list:
    out = []
    for f in COMPARED:
        a, b = o[f], n[f]
        if a == b:
            continue
        if f == "sha256":
            out.append("content")
        elif f == "mode":
            out.append(f"mode {a:04o}->{b:04o}")
        elif f == "target":
            out.append(f"target {ptext(a)}->{ptext(b)}")
        elif f == "conffile":
            out.append("became a conffile" if b else "no longer a conffile")
        elif f == "md5_status":
            word = {"ok": "ok", "modified": "mismatch", None: "none"}
            out.append(f"checksum {word[a]}->{word[b]}")
        else:
            out.append(f"{f} {a if a is not None else '-'}->{b if b is not None else '-'}")
    if not out and o["size"] != n["size"]:
        out.append(f"size {o['size']}->{n['size']}")
    return out


def fmt_owners(names: list) -> str:
    return ",".join(names) if names else "unowned"


def owner_line(names: list, old_pkgs: dict, new_pkgs: dict, e) -> str:
    """Owning packages with versions, then the package checksum state of entry e."""
    parts = []
    for name in names:
        if name.startswith("("):
            parts.append(name)
            continue
        a, b = old_pkgs.get(name), new_pkgs.get(name)
        if a == b:
            parts.append(f"{name} {b}")
        elif a is None:
            parts.append(f"{name} {b} (newly installed)")
        elif b is None:
            parts.append(f"{name} {a} (removed)")
        else:
            parts.append(f"{name} {a} -> {b}")
    if not parts:
        text = "none"
    elif len(parts) > 3:
        text = ", ".join(parts[:3]) + f", +{len(parts) - 3} more"
    else:
        text = ", ".join(parts)
    if e is not None:
        if e["conffile"]:
            state = {"ok": "conffile, as packaged", "modified": "conffile, modified"}.get(
                e["md5_status"], "conffile")
            text += f" ({state})"
        elif e["md5_status"]:
            text += " (checksum ok)" if e["md5_status"] == "ok" else " (checksum mismatch)"
    return text


# ----------------------------------------------------------------- classifying

class Classifier:
    def __init__(self, user_rules: list, old_pkgs: dict, new_pkgs: dict):
        self.user_rules = user_rules
        self.old_pkgs, self.new_pkgs = old_pkgs, new_pkgs
        self.changed = {p for p in set(old_pkgs) | set(new_pkgs) if old_pkgs.get(p) != new_pkgs.get(p)}

    def pkg_change(self, name: str) -> str:
        a, b = self.old_pkgs.get(name), self.new_pkgs.get(name)
        if a is None:
            return f"{name} installed {b}"
        if b is None:
            return f"{name} removed"
        return f"{name} {a}->{b}"

    def _rule(self, action: str, pattern: str, source: str):
        if action == "generated":
            if self.changed:
                return ("explained", "generated file, and packages changed",
                        f"generated {pattern} ({source})")
            return ("alarm", "generated file, but no package changed",
                    f"generated {pattern} ({source})")
        return action, f"matches {source} rule", f"{action} {pattern} ({source})"

    def classify(self, path: str, o, n, own_o: list, own_n: list):
        """(class, reason, rule): class is alarm|notice|explained|ignore, and
        rule is the rule that decided it, or None."""
        result = self._classify(path, o, n, own_o, own_n)
        return result if len(result) == 3 else result + (None,)

    def _classify(self, path, o, n, own_o, own_n):
        m = first_match(self.user_rules, path)
        if m:
            return self._rule(*m, "config")

        if n is not None:
            if n["mode"] & SETUID_SETGID & ~(o["mode"] if o is not None else 0):
                return "alarm", "setuid/setgid bit added"
            if n["md5_status"] == "modified" and not n["conffile"]:
                return "alarm", f"content doesn't match {fmt_owners(own_n)}'s package checksum"
            if n["type"] in ("C", "B") and not path.startswith("/dev/"):
                return "alarm", "device node outside /dev"
            if n["sha256"] and n["sha256"].startswith("!"):
                return "notice", f"couldn't be hashed this run ({n['sha256'][1:]})"
            if n["conffile"] and n["md5_status"] == "modified":
                return "notice", f"conffile of {fmt_owners(own_n)}, differs from the packaged version"

        all_owners = sorted(set(own_o) | set(own_n))
        real = [x for x in all_owners if not x.startswith("(")]
        updated = [x for x in real if x in self.changed]
        if updated:
            return "explained", "owning package changed: " + "; ".join(self.pkg_change(x) for x in updated)
        if (n is not None and n["conffile"]) or (o is not None and o["conffile"]):
            return "notice", f"conffile of {fmt_owners(real)} (package unchanged)"
        if any(x.startswith("(alternatives:") for x in all_owners):
            if self.changed:
                return "explained", "alternatives link, and packages changed"
            return "notice", "alternatives link, but no package changed"
        if "(local-diversion)" in all_owners:
            return "notice", "locally diverted path (dpkg-divert --local)"

        m = first_match(DEFAULT_RULES, path)
        if m:
            return self._rule(*m, "default")
        if real:
            return "alarm", f"owned by {fmt_owners(real)}, but that package didn't change"
        return "alarm", "no package owns this path, so nothing accounts for the change"


# ------------------------------------------------------------------------ diff

def diff(db, cls: Classifier) -> list:
    """Changes between attached run 'o' (old) and main (new), classified."""
    changes = []

    def add(kind, path, o, n):
        path_text = (n or o)["path_text"]
        own_o = owners(db, "o", path) if o is not None else []
        own_n = owners(db, "main", path) if n is not None else []
        klass, reason, rule = cls.classify(path_text, o, n, own_o, own_n)
        if klass == "ignore":
            return
        detail = ", ".join(field_changes(o, n)) if kind == "changed" else describe(n if n is not None else o)
        all_owners = sorted(set(own_o) | set(own_n))
        changes.append({"class": klass, "kind": kind, "path": path_text, "detail": detail,
                        "owner": owner_line(all_owners, cls.old_pkgs, cls.new_pkgs,
                                            n if n is not None else o),
                        "rule": rule, "reason": reason, "owners": all_owners})

    for n in db.execute("SELECT n.* FROM main.entry n LEFT JOIN o.entry o ON o.path = n.path "
                        "WHERE o.path IS NULL"):
        add("added", n["path"], None, n)
    for o in db.execute("SELECT o.* FROM o.entry o LEFT JOIN main.entry n ON n.path = o.path "
                        "WHERE n.path IS NULL"):
        add("removed", o["path"], o, None)

    differs = " OR ".join(f"n.{f} IS NOT o.{f}" for f in COMPARED)
    differs += " OR (n.type = 'F' AND n.sha256 IS NULL AND o.sha256 IS NULL AND n.size IS NOT o.size)"
    paths = [r[0] for r in db.execute(
        f"SELECT n.path FROM main.entry n JOIN o.entry o ON o.path = n.path WHERE {differs}")]
    for p in paths:
        o = db.execute("SELECT * FROM o.entry WHERE path = ?", (p,)).fetchone()
        n = db.execute("SELECT * FROM main.entry WHERE path = ?", (p,)).fetchone()
        add("changed", p, o, n)

    changes.sort(key=lambda c: (CLASS_ORDER.index(c["class"]), c["path"]))
    return changes


# ----------------------------------------------------------------------- audit

def audit(db, user_rules: list, show_unowned: bool) -> dict:
    """Check one run against package metadata. The first matching config rule
    sets a finding's class; ignore and generated drop it (a generated file
    isn't expected to match a package)."""
    findings = []
    pkgs = packages(db, "main")

    def add(klass, row, reason):
        rule = None
        m = first_match(user_rules, row["path_text"])
        if m:
            action, pattern = m
            if action in ("ignore", "generated"):
                return
            klass, rule = action, f"{action} {pattern} (config)"
        own = owners(db, "main", row["path"])
        findings.append({"class": klass, "kind": "present", "path": row["path_text"],
                         "detail": describe(row), "owner": owner_line(own, pkgs, pkgs, row),
                         "rule": rule, "reason": reason.format(owners=fmt_owners(own)),
                         "owners": own})

    for r in db.execute("SELECT * FROM entry WHERE md5_status = 'modified' AND conffile = 0"):
        add("alarm", r, "content doesn't match {owners}'s package checksum")
    for r in db.execute("SELECT * FROM entry WHERE type IN ('C', 'B') AND path_text NOT LIKE '/dev/%'"):
        add("alarm", r, "device node outside /dev")
    for r in db.execute(
            "SELECT e.* FROM entry e LEFT JOIN owner w ON w.path = e.path "
            f"WHERE w.path IS NULL AND e.type = 'F' AND (e.mode & {SETUID_SETGID}) != 0"):
        add("alarm", r, "setuid/setgid file that no package owns")
    for r in db.execute("SELECT * FROM entry WHERE sha256 LIKE '!%'"):
        add("notice", r, "couldn't be hashed")
    for r in db.execute("SELECT * FROM entry WHERE md5_status = 'modified' AND conffile = 1"):
        add("notice", r, "conffile of {owners}, differs from the packaged version")
    if show_unowned:
        for r in db.execute(
                "SELECT e.* FROM entry e LEFT JOIN owner w ON w.path = e.path "
                f"WHERE w.path IS NULL AND e.type IN ('F', 'L') AND (e.mode & {SETUID_SETGID}) = 0 "
                "AND e.path_text NOT LIKE '/etc/%'"):
            m = first_match(DEFAULT_RULES, r["path_text"])
            if m and m[0] == "generated":
                continue
            add("notice", r, "no package owns this file")

    setuid = []
    for r in db.execute(f"SELECT * FROM entry WHERE type = 'F' AND (mode & {SETUID_SETGID}) != 0 "
                        "ORDER BY path"):
        own = owners(db, "main", r["path"])
        setuid.append({"path": r["path_text"], "detail": describe(r),
                       "owner": owner_line(own, pkgs, pkgs, r), "owners": own,
                       "md5_status": r["md5_status"]})
    findings.sort(key=lambda c: (CLASS_ORDER.index(c["class"]), c["path"]))
    return {"findings": findings, "setuid": setuid}


# ---------------------------------------------------------------------- output

def print_header(title: str, runs: list, out=sys.stdout) -> None:
    print(title, file=out)
    for label, r in runs:
        line = f"  {label}: {r['host']}  {r['started']}  {r['entries']} entries"
        if r["errors"] or r["vanished"]:
            line += f"  ({r['errors']} errors, {r['vanished']} vanished)"
        if r["owners"] != "dpkg":
            line += "  [no package data]"
        print(line, file=out)


def print_items(items: list, show_explained: bool, out=sys.stdout) -> None:
    sigil = {"added": "+", "removed": "-", "changed": "~", "present": "*"}
    label = {"added": "entry:", "removed": "was:", "changed": "changed:", "present": "entry:"}
    for klass in CLASS_ORDER:
        group = [c for c in items if c["class"] == klass]
        if not group:
            continue
        print(file=out)
        if klass == "explained" and not show_explained:
            print(f"EXPLAINED ({len(group)}, use --all to list)", file=out)
            continue
        print(f"{klass.upper()} ({len(group)})", file=out)
        for c in group:
            print(f"  {sigil[c['kind']]} {c['path']}", file=out)
            print(f"      {label[c['kind']]:<9} {c['detail']}", file=out)
            print(f"      {'owner:':<9} {c['owner']}", file=out)
            if c["rule"]:
                print(f"      {'rule:':<9} {c['rule']}", file=out)


def exit_code(items: list, strict: bool) -> int:
    alarming = {"alarm", "notice"} if strict else {"alarm"}
    return 1 if any(i["class"] in alarming for i in items) else 0


def diff_command(cfg, args, out=sys.stdout) -> int:
    if len(args.runs) == 2:
        old_path, new_path = args.runs
    elif not args.runs:
        old_path, new_path = latest_two(args.dir)
    else:
        raise ZcheckError("give two runs (OLD NEW), or none to compare the latest two")
    db = open_runs(new_path, old_path)
    old, new = run_info(db, "o", old_path), run_info(db, "main", new_path)
    if old["host"] != new["host"] and not args.allow_host_mismatch:
        raise ZcheckError(f"runs are from different hosts ({old['host']}, {new['host']}); "
                          f"use --allow-host-mismatch to compare anyway")
    cls = Classifier(cfg.rules, packages(db, "o"), packages(db, "main"))
    items = diff(db, cls)
    pkg_changes = [cls.pkg_change(p) for p in sorted(cls.changed)]
    if args.json:
        json.dump({"old": old, "new": new, "packages": pkg_changes, "changes": items}, out, indent=1)
        print(file=out)
    else:
        print_header("zcheck diff", [("old", old), ("new", new)], out)
        if pkg_changes:
            print(f"\nPACKAGES ({len(pkg_changes)})", file=out)
            for p in pkg_changes:
                print(f"  {p}", file=out)
        print_items(items, args.all, out)
        if not items:
            print("\nno changes", file=out)
    return exit_code(items, args.strict)


def audit_command(cfg, args, out=sys.stdout) -> int:
    path = args.run or os.path.join(args.dir, "latest.db")
    db = open_runs(path)
    info = run_info(db, "main", path)
    result = audit(db, cfg.rules, args.unowned)
    items = result["findings"]
    if args.json:
        json.dump({"run": info, **result}, out, indent=1)
        print(file=out)
    else:
        print_header("zcheck audit", [("run", info)], out)
        print_items(items, True, out)
        if result["setuid"]:
            print(f"\nSETUID/SETGID ({len(result['setuid'])})", file=out)
            for s in result["setuid"]:
                print(f"  {s['path']}", file=out)
                print(f"      {'entry:':<9} {s['detail']}", file=out)
                print(f"      {'owner:':<9} {s['owner']}", file=out)
        if not items:
            print("\nnothing to report", file=out)
    return exit_code(items, args.strict)
