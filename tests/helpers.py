"""Test helpers: import path, temp trees, and a fake dpkg admin directory."""

import hashlib
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "lib"))
ZCHECK = os.path.join(ROOT, "bin", "zcheck")

from zcheck.config import Config  # noqa: E402
from zcheck.dpkg import Dpkg  # noqa: E402
from zcheck.scan import write_run  # noqa: E402


def md5_of(path) -> str:
    with open(path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def state_prefix(path) -> str:
    """'TYPE MODE UID:GID' as zcheck describes this file, whoever runs the tests."""
    st = os.lstat(path)
    return f"F {st.st_mode & 0o7777:04o} {st.st_uid}:{st.st_gid}"


def write(path, data=b"", mode=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())
    if mode is not None:
        os.chmod(path, mode)


class FakeDpkg:
    """Builds /var/lib/dpkg-style files under a temp directory.

    Checksums for md5= and conffiles= are taken from disk when add() is
    called, like dpkg recording them at install time: change a file
    afterwards to simulate tampering, or add() again to simulate an upgrade.
    """

    def __init__(self, admindir):
        self.admindir = admindir
        os.makedirs(os.path.join(admindir, "info"), exist_ok=True)
        self.packages = {}
        self.alternatives = {}
        self.diversions = []

    def add(self, name, version="1.0", files=(), md5=(), conffiles=(), multiarch_same=False,
            status="install ok installed"):
        self.packages[name] = dict(version=version, files=list(files), status=status,
                                   md5={f: md5_of(f) for f in md5},
                                   conffiles={f: md5_of(f) for f in conffiles},
                                   multiarch_same=multiarch_same)
        return self

    def alternative(self, group, link):
        self.alternatives[group] = link
        return self

    def divert(self, frm, to, by=":"):
        self.diversions.append((frm, to, by))
        return self

    def write(self):
        status = []
        info = os.path.join(self.admindir, "info")
        for f in os.listdir(info):
            os.unlink(os.path.join(info, f))
        for name, p in self.packages.items():
            key = f"{name}:amd64" if p["multiarch_same"] else name
            para = [f"Package: {name}", f"Status: {p['status']}",
                    "Architecture: amd64", f"Version: {p['version']}"]
            if p["multiarch_same"]:
                para.append("Multi-Arch: same")
            if p["conffiles"]:
                para.append("Conffiles:")
                para += [f" {c} {m}" for c, m in p["conffiles"].items()]
            para.append("Description: test package")
            status.append("\n".join(para))
            dirs = set()
            for f in p["files"] + list(p["conffiles"]):
                d = os.path.dirname(f)
                while d not in ("/", ""):
                    dirs.add(d)
                    d = os.path.dirname(d)
            with open(os.path.join(info, f"{key}.list"), "w") as fh:
                fh.write("/.\n" + "".join(f"{x}\n" for x in sorted(dirs) + p["files"] + list(p["conffiles"])))
            if p["md5"]:
                with open(os.path.join(info, f"{key}.md5sums"), "w") as fh:
                    fh.write("".join(f"{m}  {f.lstrip('/')}\n" for f, m in p["md5"].items()))
        with open(os.path.join(self.admindir, "status"), "w") as fh:
            fh.write("\n\n".join(status) + "\n")
        alt = os.path.join(self.admindir, "alternatives")
        os.makedirs(alt, exist_ok=True)
        for group, link in self.alternatives.items():
            with open(os.path.join(alt, group), "w") as fh:
                fh.write(f"auto\n{link}\n\n/some/choice\n10\n\n")
        with open(os.path.join(self.admindir, "diversions"), "w") as fh:
            fh.write("".join(f"{a}\n{b}\n{c}\n" for a, b, c in self.diversions))
        return self

    def load(self, verify=True) -> Dpkg:
        d = Dpkg(self.admindir, verify=verify, usrmerged={})
        d.load()
        return d


class TreeCase(unittest.TestCase):
    """A temp directory with a tree, a fake dpkg dir and a runs dir."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = os.path.realpath(self._tmp.name)
        self.tree = os.path.join(self.tmp, "tree")
        os.makedirs(self.tree)
        self.fake = FakeDpkg(os.path.join(self.tmp, "dpkg"))
        self.nruns = 0

    def tearDown(self):
        self._tmp.cleanup()

    def t(self, *parts) -> str:
        return os.path.join(self.tree, *parts)

    def scan(self, cfg=None, verify=True) -> str:
        """Scan the tree with the fake dpkg data; returns the run file."""
        self.fake.write()
        cfg = cfg or Config()
        cfg.verify = verify
        self.nruns += 1
        path = os.path.join(self.tmp, f"run{self.nruns}.db")
        write_run(cfg, [os.fsencode(self.tree)], path, self.fake.load(verify), "testhost",
                  mounts={b"/": "ext4"}, swapfiles=set())
        return path
