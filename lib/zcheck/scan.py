"""The filesystem walk behind `zcheck scan`. Each run goes to its own SQLite file."""

import glob
import hashlib
import json
import os
import socket
import sqlite3
import stat

from .common import SCHEMA, SCHEMA_VERSION, ZcheckError, md5_hasher, note, ptext, unescape_octal, utcnow
from .dpkg import Dpkg


def read_mounts(path: str = "/proc/self/mounts") -> dict:
    """{mount point bytes: fstype}; later lines (over-mounts) win."""
    mounts = {}
    try:
        with open(path, "rb") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    mounts[unescape_octal(parts[1])] = parts[2].decode()
    except OSError:
        pass
    return mounts


def read_swapfiles(path: str = "/proc/swaps") -> set:
    swaps = set()
    try:
        with open(path, "rb") as f:
            next(f, None)
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == b"file":
                    swaps.add(unescape_octal(parts[0]))
    except OSError:
        pass
    return swaps


def excluded_ancestor(p: bytes, exclude: set) -> bool:
    while True:
        if p in exclude:
            return True
        if p == b"/":
            return False
        p = os.path.dirname(p)


def scan_roots(cfg, override=None) -> list:
    """/ plus includes that fall under an excluded directory, or the override."""
    if override:
        roots = [os.fsencode(r.rstrip("/") or "/") for r in override]
    else:
        roots = [b"/"]
        for pattern in cfg.include:
            for p in sorted(glob.glob(os.fsencode(pattern))):
                if excluded_ancestor(p, cfg.exclude):
                    roots.append(p)   # otherwise / already covers it
    return list(dict.fromkeys(roots))


class Scanner:
    BATCH = 5000

    def __init__(self, cfg, dpkg: Dpkg, db: sqlite3.Connection, mounts=None, swapfiles=None):
        self.cfg, self.dpkg, self.db = cfg, dpkg, db
        self.mounts = read_mounts() if mounts is None else mounts
        swaps = read_swapfiles() if swapfiles is None else swapfiles
        self.exclude = set(cfg.exclude) | set(swaps)   # swap files: metadata only
        self.entries = self.errors = self.vanished = 0
        self.rows, self.owner_rows = [], []

    # -- bookkeeping
    def problem(self, path: bytes, err) -> None:
        if isinstance(err, FileNotFoundError):
            kind, msg = "vanished", None
            self.vanished += 1
            note(f"vanished: {ptext(path)}")
        else:
            kind, msg = "error", str(err)
            self.errors += 1
            note(f"error: {ptext(path)}: {msg}", "warning")
        self.db.execute("INSERT INTO problem VALUES (?, ?, ?)", (ptext(path), kind, msg))

    def emit(self, p: bytes, st, type_: str, **kw) -> None:
        self.entries += 1
        self.rows.append((
            p, ptext(p), type_, stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid,
            st.st_size, int(st.st_mtime), kw.get("sha256"), kw.get("target"),
            kw.get("rdev"), kw.get("fstype"), kw.get("md5_status"), int(kw.get("conffile", 0)),
        ))
        for i in self.dpkg.owner.get(p, ()):
            self.owner_rows.append((p, i))
        if len(self.rows) >= self.BATCH:
            self.flush()

    def flush(self) -> None:
        self.db.executemany("INSERT OR REPLACE INTO entry VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", self.rows)
        self.db.executemany("INSERT OR IGNORE INTO owner VALUES (?, ?)", self.owner_rows)
        self.rows, self.owner_rows = [], []

    # -- helpers
    def fs_of(self, p: bytes) -> str:
        while True:
            if p in self.mounts:
                return self.mounts[p]
            if p == b"/":
                return "?"
            p = os.path.dirname(p)

    def hash_file(self, p: bytes, st, want_md5: bool):
        """(sha256, md5 or None). sha256 is None if the file vanished."""
        try:
            fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        except OSError as e:
            self.problem(p, e)
            return (None if isinstance(e, FileNotFoundError) else "!error"), None
        try:
            fst = os.fstat(fd)
            if not stat.S_ISREG(fst.st_mode) or (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
                self.vanished += 1
                note(f"changed during scan: {ptext(p)}")
                return "!changed", None
            sha = hashlib.sha256()
            md5 = md5_hasher() if want_md5 else None
            while True:
                buf = os.read(fd, 1 << 20)
                if not buf:
                    break
                sha.update(buf)
                if md5:
                    md5.update(buf)
            return sha.hexdigest(), (md5.hexdigest() if md5 else None)
        except OSError as e:
            self.problem(p, e)
            return "!error", None
        finally:
            os.close(fd)

    # -- the walk
    def entry(self, p: bytes, pdev, pfs, stack: list) -> None:
        try:
            st = os.lstat(p)
        except OSError as e:
            self.problem(p, e)
            return
        m = st.st_mode

        if stat.S_ISLNK(m):
            try:
                target = os.readlink(p)
            except OSError as e:
                self.problem(p, e)
                return
            self.emit(p, st, "L", target=target)

        elif stat.S_ISREG(m):
            expected, conffile = self.dpkg.expected_md5(p)
            sha = md5_status = None
            if p not in self.exclude:
                sha, md5 = self.hash_file(p, st, expected is not None)
                if sha is None:
                    return
                if expected is not None and md5 is not None:
                    md5_status = "ok" if md5 in expected else "modified"
            self.emit(p, st, "F", sha256=sha, md5_status=md5_status, conffile=conffile)

        elif stat.S_ISDIR(m):
            fs, boundary = pfs, None
            if pdev is None:
                fs = self.fs_of(p)
            elif st.st_dev != pdev:
                # Another filesystem starts here. Not in the mount table means
                # something like a btrfs subvolume: same type as the parent.
                fs = self.mounts.get(p, pfs)
                boundary = fs
            if fs not in self.cfg.fstypes:
                self.emit(p, st, "M", fstype=fs)
                return
            self.emit(p, st, "D", fstype=boundary)
            if pdev is None or p not in self.exclude:
                stack.append((p, st.st_dev, fs))

        elif stat.S_ISCHR(m) or stat.S_ISBLK(m):
            self.emit(p, st, "C" if stat.S_ISCHR(m) else "B",
                      rdev=f"{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}")
        elif stat.S_ISFIFO(m):
            self.emit(p, st, "P")
        elif stat.S_ISSOCK(m):
            self.emit(p, st, "S")
        else:
            self.emit(p, st, "?")

    def scan(self, root: bytes) -> None:
        stack = []
        self.entry(root, None, None, stack)
        while stack:
            d, dev, fs = stack.pop()
            try:
                with os.scandir(d) as it:
                    names = [e.name for e in it]
            except OSError as e:
                self.problem(d, e)
                continue
            for name in names:
                self.entry(os.path.join(d, name), dev, fs, stack)


def write_run(cfg, roots: list, db_path: str, dpkg: Dpkg, host: str, mounts=None, swapfiles=None):
    """Scan roots into a new SQLite file at db_path. Returns the Scanner."""
    db = sqlite3.connect(db_path)
    try:
        db.executescript("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;" + SCHEMA)
        db.executemany("INSERT INTO package VALUES (?, ?, ?, ?)",
                       [(i, n) + dpkg.versions.get(n, (None, None)) for i, n in enumerate(dpkg.names)])
        db.execute("INSERT INTO run (schema_version, host, started, owners, config) VALUES (?,?,?,?,?)", (
            SCHEMA_VERSION, host, utcnow(), "dpkg" if dpkg.loaded else "off",
            json.dumps({"roots": [ptext(r) for r in roots],
                        "exclude": sorted(ptext(p) for p in cfg.exclude),
                        "fstypes": sorted(cfg.fstypes), "verify": cfg.verify}),
        ))
        scanner = Scanner(cfg, dpkg, db, mounts=mounts, swapfiles=swapfiles)
        for r in roots:
            scanner.scan(r)
        scanner.flush()
        db.execute("UPDATE run SET finished=?, entries=?, errors=?, vanished=?",
                   (utcnow(), scanner.entries, scanner.errors, scanner.vanished))
        db.execute("CREATE INDEX owner_package ON owner(package_id)")
        db.commit()
    finally:
        db.close()
    return scanner


def prune_runs(runs_dir: str, keep: int) -> None:
    runs = sorted(f for f in os.listdir(runs_dir) if f.endswith(".db") and not f.startswith("."))
    for f in (runs[:-keep] if keep > 0 else []):
        try:
            os.unlink(os.path.join(runs_dir, f))
            note(f"pruned old run {f}")
        except OSError as e:
            note(f"warning: couldn't prune {f}: {e}", "warning")


def scan_command(cfg, args) -> int:
    """`zcheck scan`: write a run; 0 clean, 1 if entries couldn't be read."""
    host = socket.gethostname()
    if args.output:
        final, runs_dir = os.path.abspath(args.output), None
    else:
        runs_dir = os.path.join(args.dir, "runs")
        os.makedirs(runs_dir, mode=0o700, exist_ok=True)
        final = os.path.join(runs_dir, f"{host}-{utcnow().replace(':', '')}.db")
    tmp = os.path.join(os.path.dirname(final), f".{os.path.basename(final)}.tmp")

    roots = scan_roots(cfg, args.root)
    dpkg = Dpkg(args.dpkg_admindir, cfg.verify)
    if cfg.owners:
        dpkg.load()

    note(f"starting run -> {final}")
    try:
        if os.path.exists(tmp):
            os.unlink(tmp)
        scanner = write_run(cfg, roots, tmp, dpkg, host)
        os.replace(tmp, final)
    except (OSError, sqlite3.Error) as e:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise ZcheckError(f"scan failed: {e}")

    if runs_dir:
        latest = os.path.join(args.dir, "latest.db")
        link_tmp = latest + ".tmp"
        try:
            os.unlink(link_tmp)
        except FileNotFoundError:
            pass
        os.symlink(os.path.relpath(final, args.dir), link_tmp)
        os.replace(link_tmp, latest)
        prune_runs(runs_dir, args.keep)

    note(f"done: {scanner.entries} entries, {scanner.errors} errors, {scanner.vanished} vanished",
         "warning" if scanner.errors else "info")
    return 1 if scanner.errors else 0
