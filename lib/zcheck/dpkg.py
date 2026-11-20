"""Ownership, conffiles, checksums and versions from dpkg's database.

Handles merged /usr (dpkg may list /bin/ls while the file is /usr/bin/ls),
dpkg-divert (a diverted-away file belongs to the original package, the file
at the original path to the diverting package), and update-alternatives
links, which no package lists ("(alternatives:NAME)").
"""

import os
import re

from .common import note

USRMERGE_DIRS = (b"bin", b"sbin", b"lib", b"lib32", b"lib64", b"libx32")


def detect_usrmerge(root: bytes = b"/") -> dict:
    """{b'/bin': b'/usr/bin', ...} for top-level dirs that are symlinks into /usr."""
    merged = {}
    for d in USRMERGE_DIRS:
        try:
            target = os.readlink(os.path.join(root, d))
        except OSError:
            continue
        if target.strip(b"/") == b"usr/" + d:
            merged[b"/" + d] = b"/usr/" + d
    return merged


class Dpkg:
    def __init__(self, admindir: str = "/var/lib/dpkg", verify: bool = True, usrmerged=None):
        self.admindir = admindir
        self.verify = verify
        self.usrmerged = detect_usrmerge() if usrmerged is None else usrmerged
        self.names = []          # id -> name
        self.ids = {}            # name (and base name without :arch) -> id
        self.versions = {}       # name -> (version, status)
        self.owner = {}          # path -> set of ids
        self.md5 = {}            # path -> {id: md5}
        self.conffile = {}       # path -> {id: md5}
        self.div_to_from = {}    # diverted-to path -> original path
        self.loaded = False

    # -- package ids
    def pkg(self, name: str) -> int:
        if name in self.ids:
            return self.ids[name]
        self.names.append(name)
        i = len(self.names) - 1
        self.ids[name] = i
        self.ids.setdefault(name.split(":", 1)[0], i)
        return i

    def owner_names(self, p: bytes) -> list:
        return sorted(self.names[i] for i in self.owner.get(p, ()))

    def spellings(self, p: bytes) -> tuple:
        """The path as dpkg lists it, plus its merged-/usr spelling if different."""
        m = re.match(rb"^(/[^/]+)(/.*)$", p)
        if m and m.group(1) in self.usrmerged:
            return (p, self.usrmerged[m.group(1)] + m.group(2))
        return (p,)

    # -- loading
    def load(self) -> bool:
        info = os.path.join(self.admindir, "info")
        if not os.path.isdir(info):
            return False
        self._load_status()
        self._load_info(info)
        self._load_alternatives()
        self._load_diversions()
        self.loaded = True
        return True

    def _load_status(self) -> None:
        try:
            with open(os.path.join(self.admindir, "status"), "rb") as f:
                data = f.read()
        except OSError as e:
            note(f"warning: can't read dpkg status: {e}")
            return
        for para in data.split(b"\n\n"):
            fields, conffiles, current = {}, [], None
            for line in para.split(b"\n"):
                if line[:1] in (b" ", b"\t"):
                    if current == b"Conffiles":
                        conffiles.append(line.split())
                    continue
                key, _, value = line.partition(b":")
                current = key
                fields[key] = value.strip()
            name = fields.get(b"Package", b"").decode()
            status = fields.get(b"Status", b"").decode()
            if not name or status.endswith("not-installed"):
                continue
            arch = fields.get(b"Architecture", b"").decode()
            if fields.get(b"Multi-Arch") == b"same" and arch:
                name = f"{name}:{arch}"      # matches the info file naming
            self.versions[name] = (fields.get(b"Version", b"").decode(), status)
            i = self.pkg(name)
            for cf in conffiles:
                if len(cf) >= 2 and re.fullmatch(rb"[0-9a-f]{32}", cf[1]):
                    for p in self.spellings(cf[0]):
                        self.conffile.setdefault(p, {})[i] = cf[1].decode()

    def _load_info(self, info: str) -> None:
        for fn in sorted(os.listdir(info)):
            if fn.endswith(".list"):
                self._read_list(os.path.join(info, fn), self.pkg(fn[:-5]))
            elif fn.endswith(".md5sums") and self.verify:
                self._read_md5sums(os.path.join(info, fn), self.pkg(fn[:-8]))

    def _read_list(self, path: str, i: int) -> None:
        try:
            with open(path, "rb") as f:
                for line in f:
                    p = line.rstrip(b"\n")
                    if p and p != b"/.":
                        for s in self.spellings(p):
                            self.owner.setdefault(s, set()).add(i)
        except OSError as e:
            note(f"warning: {path}: {e}")

    def _read_md5sums(self, path: str, i: int) -> None:
        try:
            with open(path, "rb") as f:
                for line in f:
                    line = line.rstrip(b"\n")
                    if len(line) > 34:           # "<32 hex>  relative/path"
                        p = b"/" + line[34:].lstrip(b"/")
                        for s in self.spellings(p):
                            self.md5.setdefault(s, {})[i] = line[:32].decode()
        except OSError as e:
            note(f"warning: {path}: {e}")

    def _load_alternatives(self) -> None:
        # One file per group: mode, master link, (slave name, slave link)
        # pairs, blank line, then the choices.
        d = os.path.join(self.admindir, "alternatives")
        try:
            groups = sorted(g for g in os.listdir(d) if not g.startswith("."))
        except OSError:
            return
        for group in groups:
            try:
                with open(os.path.join(d, group), "rb") as f:
                    lines = f.read().split(b"\n")
            except OSError:
                continue
            if len(lines) < 2:
                continue
            i = self.pkg(f"(alternatives:{group})")
            links = [(group.encode(), lines[1])]
            k = 2
            while k + 1 < len(lines) and lines[k]:
                links.append((lines[k], lines[k + 1]))
                k += 2
            for name, link in links:
                for p in self.spellings(link) + (b"/etc/alternatives/" + name,):
                    self.owner.setdefault(p, {i})

    def _load_diversions(self) -> None:
        # Triplets: original path, diverted-to path, diverting package (":" = local).
        try:
            with open(os.path.join(self.admindir, "diversions"), "rb") as f:
                lines = f.read().split(b"\n")
        except OSError:
            return
        for k in range(0, len(lines) - 2, 3):
            frm, to, by = lines[k], lines[k + 1], lines[k + 2]
            if not frm or not to:
                continue
            byi = self.pkg("(local-diversion)" if by == b":" else by.decode())
            froms, tos = self.spellings(frm), self.spellings(to)
            orig = set()
            for p in froms:
                orig |= self.owner.get(p, set()) - {byi}
            for p in tos:
                if orig:
                    self.owner[p] = set(orig)
                else:
                    self.owner.pop(p, None)
                self.div_to_from[p] = frm
            for p in froms:
                self.owner[p] = {byi}

    # -- queries
    def expected_md5(self, p: bytes):
        """(set of acceptable md5s or None, is_conffile) for a file at path p."""
        owners = self.owner.get(p)
        if not owners:
            return None, False
        if p in self.conffile:
            sums = {m for i, m in self.conffile[p].items() if i in owners}
            if sums:
                return (sums if self.verify else None), True
        if not self.verify:
            return None, False
        direct = self.md5.get(p, {})
        diverted = {}
        frm = self.div_to_from.get(p)
        if frm:
            for s in self.spellings(frm):
                diverted.update(self.md5.get(s, {}))
        sums = set()
        for i in owners:
            if i in direct:
                sums.add(direct[i])
            elif i in diverted:
                sums.add(diverted[i])
        return (sums or None), False
