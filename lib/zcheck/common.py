"""Pieces shared by zcheck and zcheck-diff: the run schema, text helpers and
the "keyword argument" config-file format both tools use."""

import hashlib
import re
import sys
import time
from datetime import datetime, timezone

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE run (
    schema_version INTEGER NOT NULL,
    host           TEXT NOT NULL,
    started        TEXT NOT NULL,   -- ISO 8601 UTC
    finished       TEXT,
    entries        INTEGER,
    errors         INTEGER,
    vanished       INTEGER,
    owners         TEXT,            -- 'dpkg' or 'off'
    config         TEXT             -- JSON: effective roots/excludes/fstypes
);
CREATE TABLE package (
    id      INTEGER PRIMARY KEY,
    name    TEXT NOT NULL UNIQUE,   -- as dpkg names its info files, e.g. libc6:amd64
    version TEXT,
    status  TEXT
);
CREATE TABLE entry (
    path       BLOB PRIMARY KEY,
    path_text  TEXT NOT NULL,
    type       TEXT NOT NULL,       -- F L D M C B P S ?
    mode       INTEGER NOT NULL,    -- permission bits incl. setuid/setgid/sticky
    uid        INTEGER NOT NULL,
    gid        INTEGER NOT NULL,
    size       INTEGER,
    mtime      INTEGER,
    sha256     TEXT,                -- F: digest, NULL if excluded, '!error' / '!changed'
    target     BLOB,                -- L
    rdev       TEXT,                -- C/B: 'major:minor'
    fstype     TEXT,                -- D where a filesystem starts, and M
    md5_status TEXT,                -- F with a package checksum: 'ok' / 'modified'
    conffile   INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
CREATE TABLE owner (
    path       BLOB NOT NULL,
    package_id INTEGER NOT NULL REFERENCES package(id),
    PRIMARY KEY (path, package_id)
) WITHOUT ROWID;
CREATE TABLE problem (
    path_text TEXT NOT NULL,
    kind      TEXT NOT NULL,        -- 'error' or 'vanished'
    message   TEXT
);
"""

# Entry types, as stored in entry.type.
TYPES = {
    "F": "file", "L": "symlink", "D": "directory", "M": "unscanned mount",
    "C": "char device", "B": "block device", "P": "fifo", "S": "socket", "?": "other",
}

SETUID_SETGID = 0o6000


class ZcheckError(Exception):
    """A user-facing error: bad config, unusable input. Commands exit 2."""


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def note(msg: str) -> None:
    print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {msg}", file=sys.stderr, flush=True)


def ptext(p) -> str:
    """Readable text for a bytes path; undecodable bytes become \\xNN."""
    if p is None:
        return "-"
    return bytes(p).decode("utf-8", "backslashreplace")


def unescape_octal(b: bytes) -> bytes:
    r"""Undo the \ooo escaping used by /proc/self/mounts and /proc/swaps."""
    return re.sub(rb"\\([0-7]{3})", lambda m: bytes([int(m.group(1), 8)]), b)


def md5_hasher():
    """MD5 for comparing with dpkg's checksums, not for security."""
    try:
        return hashlib.md5(usedforsecurity=False)
    except TypeError:          # Python < 3.9
        return hashlib.md5()


def read_directives(path: str, allowed):
    """Parse a 'keyword argument' file: '#' starts a comment, blank lines are
    skipped, and every directive needs an argument. Returns a list of
    (line number, keyword, argument). A missing file is an empty list."""
    try:
        f = open(path, encoding="utf-8", errors="surrogateescape")
    except FileNotFoundError:
        return []
    except OSError as e:
        raise ZcheckError(f"{path}: {e.strerror}")
    out = []
    with f:
        for n, line in enumerate(f, 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if parts[0] not in allowed:
                raise ZcheckError(f"{path}:{n}: unknown directive '{parts[0]}' "
                                  f"(expected one of: {', '.join(allowed)})")
            if len(parts) != 2:
                raise ZcheckError(f"{path}:{n}: '{parts[0]}' needs an argument")
            out.append((n, parts[0], parts[1].strip()))
    return out
