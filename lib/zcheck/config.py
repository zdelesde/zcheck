"""/etc/zcheck.conf: scan settings and classification rules in one file.

Scan directives (what `zcheck scan` walks and records):
  exclude PATH     don't descend into directory PATH / don't hash file PATH
  unexclude PATH   remove one of the default excludes
  include PATH     scan PATH even though it's under an excluded directory
                   (globs allowed, e.g. /home/*/.ssh)
  fstype TYPE      also descend into filesystems of TYPE
  owners on|off    read dpkg ownership (default on)
  verify on|off    compare files with package checksums (default on)

Rules (how `zcheck diff` and `zcheck audit` class what they find; first match
wins, checked before the built-in logic):
  ignore GLOB      drop it
  notice GLOB      class as notice
  alarm GLOB       class as alarm
  generated GLOB   diff: explained if any package changed between the runs,
                   else alarm. audit: dropped.
GLOB is matched against the whole path with fnmatch; "*" also matches "/".
"""

import os

from .common import ZcheckError, read_directives

DEFAULT_PATH = "/etc/zcheck.conf"

DEFAULT_EXCLUDE = ["/root", "/home", "/var", "/tmp", "/dev", "/sys", "/proc", "/run",
                   "/net", "/mnt", "/media", "/srv", "/lost+found"]
DEFAULT_INCLUDE = ["/root/.ssh", "/root/.bashrc", "/root/.profile",
                   "/home/*/.ssh", "/home/*/.bashrc", "/home/*/.profile",
                   "/var/spool/cron"]
DEFAULT_FSTYPES = ["ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "vfat", "f2fs", "jfs"]

SCAN_KEYS = ("exclude", "unexclude", "include", "fstype", "owners", "verify")
RULE_KEYS = ("ignore", "notice", "alarm", "generated")


class Config:
    def __init__(self):
        self.exclude = {os.fsencode(p) for p in DEFAULT_EXCLUDE}
        self.include = list(DEFAULT_INCLUDE)
        self.fstypes = set(DEFAULT_FSTYPES)
        self.owners = True
        self.verify = True
        self.rules = []          # [(action, glob)] in file order
        self.path = None

    @classmethod
    def load(cls, path: str = DEFAULT_PATH) -> "Config":
        cfg = cls()
        cfg.path = path
        for n, key, value in read_directives(path, SCAN_KEYS + RULE_KEYS):
            if key in RULE_KEYS:
                cfg.rules.append((key, value))
                continue
            if key in ("exclude", "unexclude", "include") and len(value) > 1:
                value = value.rstrip("/")
            if key == "exclude":
                cfg.exclude.add(os.fsencode(value))
            elif key == "unexclude":
                cfg.exclude.discard(os.fsencode(value))
            elif key == "include":
                cfg.include.append(value)
            elif key == "fstype":
                cfg.fstypes.add(value)
            else:                                   # owners, verify
                if value not in ("on", "off"):
                    raise ZcheckError(f"{path}:{n}: {key} must be 'on' or 'off'")
                setattr(cfg, key, value == "on")
        return cfg
